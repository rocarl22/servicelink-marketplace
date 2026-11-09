"""Thin QML bridge. Every method is a @Slot that delegates to a service."""
import json
import logging
import os
import tempfile
from urllib.parse import quote_plus
from PySide6.QtCore import QObject, Slot, QUrl, Signal
from PySide6.QtGui import QGuiApplication, QDesktopServices

from . import database as db
from .services import (
    settings, passwords, categories, accounts, machine_id,
)
from .services.sessions import IdleSession

log = logging.getLogger("servicelink.bridge")


class Bridge(QObject):
    sessionActivity = Signal()

    def __init__(self):
        super().__init__()
        db.init_db()
        try:
            accounts.expire_stale_holds()
        except Exception:
            log.exception("expire_stale_holds failed")
        self._user_session = IdleSession()
        self._admin_session = IdleSession()

    def _user_session_active(self, touch: bool = True) -> bool:
        had_session = bool(self._user_session.identifier)
        active = self._user_session.is_active(touch=touch)
        if had_session and not active:
            log.info("User session expired due to inactivity")
        return active

    def _admin_session_active(self, touch: bool = True) -> bool:
        had_session = bool(self._admin_session.identifier)
        active = self._admin_session.is_active(touch=touch)
        if had_session and not active:
            log.info("Administrator session expired due to inactivity")
        return active

    def _owns(self, account_id: str) -> bool:
        return self._user_session.owns(account_id)

    def _owns_admin(self, admin_id: str) -> bool:
        return self._admin_session.owns(admin_id)

    def _deny(self, action: str):
        log.warning("Blocked %s without matching session", action)
        return False

    @Slot(str)
    def beginSession(self, accountId):
        if accountId:
            self._user_session.start(accountId)

    @Slot(result=bool)
    def touchSession(self):
        """Refresh the active session after real UI activity."""
        user_active = self._user_session_active()
        admin_active = self._admin_session_active()
        return user_active or admin_active

    @Slot()
    def notifyUserActivity(self):
        """Called by the Qt application event filter for keyboard/mouse input."""
        user_active = self._user_session_active()
        admin_active = self._admin_session_active()
        if user_active or admin_active:
            self.sessionActivity.emit()

    @Slot()
    def signOut(self):
        self._user_session.clear()

    @Slot(result=str)
    def getIconDir(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, "qml", "assets", "Icons").replace("\\", "/")

    @Slot(str, str, result=str)
    def getTintedIcon(self, iconName, tintHex):
        try:
            from . import icon_tint
            icon_dir = self.getIconDir()
            svg_path = os.path.join(icon_dir, iconName)
            png = icon_tint.tint_icon(svg_path, tintHex)
            return png.replace("\\", "/") if png else ""
        except Exception:
            log.exception("getTintedIcon failed")
            return ""

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    @Slot(result=str)
    def getThemeMode(self):
        try:
            return settings.get_theme_mode()
        except Exception:
            log.exception("getThemeMode failed")
            return "auto"

    @Slot(str, result=bool)
    def setThemeMode(self, mode):
        try:
            settings.set_theme_mode(mode)
            return True
        except Exception:
            log.exception("setThemeMode failed")
            return False

    @Slot(result=str)
    def getSystemColorScheme(self):
        try:
            from PySide6.QtCore import Qt
            scheme = QGuiApplication.styleHints().colorScheme()
            return "dark" if scheme == Qt.ColorScheme.Dark else "light"
        except Exception:
            log.exception("getSystemColorScheme failed")
            return "light"

    @Slot(result=str)
    def getDbPath(self):
        return db.DB_PATH

    @Slot(result=str)
    def getLogPath(self):
        return os.path.join(db.DATA_DIR, "app.log")

    @Slot(str, result=bool)
    def openAreaMap(self, area):
        """Open an OpenStreetMap search for a user-entered area (no API key)."""
        if not self._user_session_active():
            self._deny("openAreaMap")
            return False
        query = " ".join((area or "").split())[:160]
        if not query:
            return False
        try:
            url = QUrl("https://www.openstreetmap.org/search?query=" + quote_plus(query))
            return bool(QDesktopServices.openUrl(url))
        except Exception:
            log.exception("openAreaMap failed")
            return False

    @Slot(str, str, result=str)
    def exportMyData(self, accountId, outputPath):
        """Write a privacy-safe JSON export for the authenticated account."""
        if not self._owns(accountId):
            self._deny("exportMyData")
            return "ERROR: Sign in again before exporting your data."
        temp_path = ""
        try:
            from .services import data_export
            raw_path = (outputPath or "").strip()
            if raw_path.startswith("file:"):
                raw_path = QUrl(raw_path).toLocalFile()
            target = os.path.abspath(os.path.expanduser(raw_path))
            if not target or not target.lower().endswith(".json"):
                return "ERROR: Choose a JSON file destination."
            parent = os.path.dirname(target)
            if not parent or not os.path.isdir(parent):
                return "ERROR: The selected folder does not exist."
            payload = data_export.export_account_data(accountId)
            fd, temp_path = tempfile.mkstemp(
                prefix=".servicelink-export-", suffix=".tmp", dir=parent
            )
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, target)
            temp_path = ""
            if os.name != "nt":
                try:
                    os.chmod(target, 0o600)
                except OSError:
                    log.warning("Could not restrict permissions on data export file")
            log.info("Account data export completed for account %s", accountId)
            return "OK: Your data export has been saved."
        except Exception:
            log.exception("exportMyData failed")
            return "ERROR: The data export could not be completed. Please try another location."
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------

    @Slot(result=str)
    def suggestPassword(self):
        try:
            return passwords.suggest()
        except Exception:
            log.exception("suggestPassword failed")
            return ""

    @Slot(str, result=str)
    def passwordStrength(self, password):
        try:
            return passwords.strength(password)
        except Exception:
            log.exception("passwordStrength failed")
            return "weak"

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    @Slot(str, str, str, str, str, str, bool, bool, str, result=str)
    def createAccount(self, role, fullName, phone, email, password,
                      passwordConfirm, termsAccepted, roleLocked,
                      serviceFamily):
        try:
            ok, payload = accounts.create_account(
                role=role, full_name=fullName, phone=phone, email=email,
                password=password, password_confirm=passwordConfirm,
                terms_accepted=termsAccepted, role_locked=roleLocked,
                service_family=serviceFamily,
                device_key=machine_id.get_machine_id(),
            )
            if ok:
                self._user_session.start(payload)
                return "OK:" + payload
            return "ERROR: " + payload
        except Exception:
            log.exception("createAccount failed")
            return "ERROR: Account could not be created. Please try again."

    @Slot(str, str, result=str)
    def signIn(self, phone, password):
        try:
            ok, result = accounts.sign_in(
                phone, password,
                device_key=machine_id.get_machine_id(),
            )
            if not ok:
                return "ERROR: " + result
            self._user_session.start(result)
            account = accounts.get_account(result)
            if account.get("password_upgrade_required"):
                return "UPGRADE:" + result
            return "OK:" + result
        except Exception:
            log.exception("signIn failed")
            return "ERROR: Sign in could not be completed. Please try again."

    @Slot(str, result="QVariantMap")
    def getAccount(self, accountId):
        if not self._owns(accountId):
            self._deny("getAccount")
            return {}
        try:
            return accounts.get_account(accountId)
        except Exception:
            log.exception("getAccount failed")
            return {}

    @Slot(str, result="QVariantMap")
    def getAccountSummary(self, accountId):
        if not self._owns(accountId):
            self._deny("getAccountSummary")
            return {}
        try:
            return accounts.get_account_summary(accountId)
        except Exception:
            log.exception("getAccountSummary failed")
            return {}

    @Slot(str, str, str, str, str, result=str)
    def updateProfile(self, accountId, displayName, area, bio, workPhotoPath):
        if not self._owns(accountId):
            self._deny("updateProfile")
            return "ERROR: Your session has expired."
        try:
            ok, msg = accounts.update_profile(
                accountId, displayName, area, bio, workPhotoPath or "",
            )
            return ("OK: " if ok else "ERROR: ") + msg
        except Exception:
            log.exception("updateProfile failed")
            return "ERROR: Profile could not be saved."

    @Slot(str, str, str, str, str, str, result=str)
    def saveProfileDraft(self, accountId, displayName, area, bio, role, serviceFamily):
        if not self._owns(accountId):
            self._deny("saveProfileDraft")
            return "ERROR: Your session has expired."
        try:
            ok, msg = accounts.save_profile_draft(
                accountId, displayName, area, bio, role, serviceFamily,
            )
            return ("OK: " if ok else "ERROR: ") + msg
        except Exception:
            log.exception("saveProfileDraft failed")
            return "ERROR: Draft could not be saved."

    @Slot(str, str, str, str, str, str, str, result=str)
    def completeProfile(self, accountId, displayName, area, bio,
                        workPhotoPath, role, serviceFamily):
        if not self._owns(accountId):
            self._deny("completeProfile")
            return "ERROR: Your session has expired."
        try:
            ok, msg = accounts.complete_profile(
                accountId, displayName, area, bio,
                workPhotoPath or "", role, serviceFamily,
            )
            return ("OK: " if ok else "ERROR: ") + msg
        except Exception:
            log.exception("completeProfile failed")
            return "ERROR: Profile could not be saved."

    @Slot(str, str, str, str, result=str)
    def changePassword(self, accountId, currentPassword, newPassword, confirmation):
        if not self._owns(accountId):
            self._deny("changePassword")
            return "ERROR: Your session has expired."
        try:
            ok, msg = accounts.change_password(
                accountId, currentPassword, newPassword, confirmation,
            )
            return ("OK: " if ok else "ERROR: ") + msg
        except Exception:
            log.exception("changePassword failed")
            return "ERROR: Password could not be updated."

    @Slot(str, str, result=str)
    def setWorkPhoto(self, accountId, srcPath):
        if not self._owns(accountId):
            self._deny("setWorkPhoto")
            return "ERROR: Your session has expired."
        try:
            from .services import accounts as accounts_svc
            ok, result = accounts_svc.set_work_photo(accountId, srcPath or "")
            if ok:
                return "OK:" + result
            return "ERROR: " + result
        except Exception:
            log.exception("setWorkPhoto failed")
            return "ERROR: Photo could not be saved."

    @Slot(str, result=str)
    def removeWorkPhoto(self, accountId):
        if not self._owns(accountId):
            self._deny("removeWorkPhoto")
            return "ERROR: Your session has expired."
        try:
            from .services import accounts as accounts_svc
            ok, msg = accounts_svc.remove_work_photo(accountId)
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("removeWorkPhoto failed")
            return "ERROR: Photo could not be removed."

    @Slot(str, result=bool)
    def markPasswordWarningSeen(self, accountId):
        if not self._owns(accountId):
            self._deny("markPasswordWarningSeen")
            return False
        try:
            return accounts.mark_password_warning_seen(accountId)
        except Exception:
            log.exception("markPasswordWarningSeen failed")
            return False

    # ------------------------------------------------------------------
    # Service requests
    # ------------------------------------------------------------------

    @Slot(str, str, str, str, str, str, str, str, result=str)
    def createServiceRequest(self, accountId, category, description,
                             area, preferredTime, budgetText, providerId, mode):
        # budgetText is accepted for backwards compatibility but no
        # longer stored; prices are agreed on the job, not the request.
        if not self._owns(accountId):
            self._deny("createServiceRequest")
            return "ERROR: Your session has expired."
        try:
            from .services import requests as requests_svc
            ok, result = requests_svc.create_request(
                client_account_id=accountId,
                category=category, description=description, area=area,
                preferred_time=preferredTime,
                provider_account_id=providerId or "", mode=mode or "",
            )
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("createServiceRequest failed")
            return "ERROR: Request could not be created."

    @Slot(str, result="QVariantList")
    def listMyRequestsAsClient(self, accountId):
        if not self._owns(accountId):
            self._deny("listMyRequestsAsClient")
            return []
        try:
            from .services import requests as requests_svc
            return requests_svc.list_client_requests(accountId)
        except Exception:
            log.exception("listMyRequestsAsClient failed")
            return []

    @Slot(str, result="QVariantList")
    def listOpenRequestsForMe(self, accountId):
        if not self._owns(accountId):
            self._deny("listOpenRequestsForMe")
            return []
        try:
            from .services import requests as requests_svc
            return requests_svc.list_open_requests_for_provider(accountId)
        except Exception:
            log.exception("listOpenRequestsForMe failed")
            return []

    @Slot(str, str, result="QVariantMap")
    def getPendingRequestBetween(self, accountId, otherAccountId):
        if not self._owns(accountId):
            self._deny("getPendingRequestBetween")
            return {}
        try:
            from .services import requests as requests_svc
            account = accounts.get_account(accountId)
            if account.get("role") == "client":
                client_id, provider_id = accountId, otherAccountId
            else:
                client_id, provider_id = otherAccountId, accountId
            return requests_svc.get_pending_request_between(client_id, provider_id)
        except Exception:
            log.exception("getPendingRequestBetween failed")
            return {}

    @Slot(str, str, result="QVariantList")
    def listOpenRequestsBetween(self, accountId, otherAccountId):
        # The acting account is whichever id the SESSION owns; the other id is only
        # the counterpart. Roles come from the session-owned account, and the
        # counterpart must hold the opposite role (see services/authz.py).
        if self._owns(accountId):
            me, other = accountId, otherAccountId
        elif self._owns(otherAccountId):
            me, other = otherAccountId, accountId
        else:
            self._deny("listOpenRequestsBetween")
            return []
        try:
            from .services import authz, requests as requests_svc
            pair = authz.resolve_client_provider(
                me, other, lambda aid: accounts.get_account(aid).get("role", ""))
            if pair is None:
                return []
            return requests_svc.list_open_requests_between(*pair)
        except Exception:
            log.exception("listOpenRequestsBetween failed")
            return []

    @Slot(result=int)
    def expireStaleRequests(self):
        try:
            from .services import requests as requests_svc
            requests_svc.expire_stale_requests()
            return 0
        except Exception:
            log.exception("expireStaleRequests failed")
            return -1

    @Slot(str, int, str, result=str)
    def cancelServiceRequest(self, accountId, requestId, reason):
        if not self._owns(accountId):
            self._deny("cancelServiceRequest")
            return "ERROR: Your session has expired."
        try:
            from .services import requests as requests_svc
            ok, result = requests_svc.cancel_request(accountId, requestId, reason or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("cancelServiceRequest failed")
            return "ERROR: Request could not be cancelled."

    @Slot(str, int, str, result=str)
    def declineRequest(self, accountId, requestId, reason):
        if not self._owns(accountId):
            self._deny("declineRequest")
            return "ERROR: Your session has expired."
        try:
            from .services import requests as requests_svc
            ok, result = requests_svc.decline_request(accountId, requestId, reason or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("declineRequest failed")
            return "ERROR: Request could not be declined."

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    @Slot(str, int, result=str)
    def acceptRequest(self, accountId, requestId):
        if not self._owns(accountId):
            self._deny("acceptRequest")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.accept_request(accountId, requestId)
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("acceptRequest failed")
            return "ERROR: The request could not be accepted."

    @Slot(str, int, str, result=str)
    def setAgreedPrice(self, accountId, jobId, priceText):
        if not self._owns(accountId):
            self._deny("setAgreedPrice")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.set_agreed_price(jobId, accountId, priceText or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("setAgreedPrice failed")
            return "ERROR: Price could not be set."

    @Slot(str, int, str, result=str)
    def cancelJob(self, accountId, jobId, reason):
        if not self._owns(accountId):
            self._deny("cancelJob")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.cancel_job(jobId, accountId, reason or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("cancelJob failed")
            return "ERROR: Job could not be cancelled."

    @Slot(str, int, str, str, bool, result=str)
    def openDispute(self, accountId, jobId, category, description, anonymous):
        if not self._owns(accountId):
            self._deny("openDispute")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.open_dispute(
                jobId, accountId, category, description, bool(anonymous))
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("openDispute failed")
            return "ERROR: Dispute could not be filed."

    @Slot(str, int, result=str)
    def withdrawDispute(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("withdrawDispute")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.withdraw_dispute(jobId, accountId)
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("withdrawDispute failed")
            return "ERROR: Could not withdraw dispute."

    @Slot(str, int, str, result=str)
    def acceptDispute(self, accountId, jobId, note):
        if not self._owns(accountId):
            self._deny("acceptDispute")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.accept_dispute(jobId, accountId, note or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("acceptDispute failed")
            return "ERROR: Could not accept dispute."

    @Slot(str, int, result="QVariantMap")
    def getDisputeForJob(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("getDisputeForJob")
            return {}
        try:
            from .services import jobs as jobs_svc
            return jobs_svc.get_dispute_for_job(jobId)
        except Exception:
            log.exception("getDisputeForJob failed")
            return {}

    @Slot(str, str, result="QVariantMap")
    def getOpenDisputeBetween(self, accountId, otherAccountId):
        if not self._owns(accountId):
            self._deny("getOpenDisputeBetween")
            return {}
        try:
            from .services import jobs as jobs_svc
            account = accounts.get_account(accountId)
            if account.get("role") == "client":
                client_id, provider_id = accountId, otherAccountId
            else:
                client_id, provider_id = otherAccountId, accountId
            return jobs_svc.get_open_dispute_between(
                client_id, provider_id, viewer_account_id=accountId)
        except Exception:
            log.exception("getOpenDisputeBetween failed")
            return {}

    @Slot(str, result="QVariantList")
    def listMyJobs(self, accountId):
        if not self._owns(accountId):
            self._deny("listMyJobs")
            return []
        try:
            from .services import jobs as jobs_svc
            return jobs_svc.list_my_jobs(accountId)
        except Exception:
            log.exception("listMyJobs failed")
            return []

    @Slot(str, int, result="QVariantMap")
    def getJob(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("getJob")
            return {}
        try:
            from .services import jobs as jobs_svc
            return jobs_svc.get_job(jobId, accountId)
        except Exception:
            log.exception("getJob failed")
            return {}

    @Slot(str, int, str, str, str, result=str)
    def advanceJob(self, accountId, jobId, action, note, evidencePath):
        if not self._owns(accountId):
            self._deny("advanceJob")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.advance(
                jobId, accountId, action,
                note=note or "", evidence_path=evidencePath or "",
            )
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("advanceJob failed")
            return "ERROR: The job could not be updated."

    @Slot(str, int, result=str)
    def closeJob(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("closeJob")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.close_job(jobId, accountId, "client_confirmed")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("closeJob failed")
            return "ERROR: The job could not be closed."

    @Slot(str, int, result=str)
    def undoJobEvent(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("undoJobEvent")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.undo_last_event(jobId, accountId)
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("undoJobEvent failed")
            return "ERROR: Could not undo."

    @Slot(str, int, str, result=str)
    def requestCorrection(self, accountId, jobId, reason):
        if not self._owns(accountId):
            self._deny("requestCorrection")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.request_correction(jobId, accountId, reason)
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("requestCorrection failed")
            return "ERROR: Correction could not be requested."

    @Slot(str, int, result=str)
    def approveCorrection(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("approveCorrection")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.approve_correction(jobId, accountId)
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("approveCorrection failed")
            return "ERROR: Correction could not be approved."

    @Slot(str, int, str, result=str)
    def rejectCorrection(self, accountId, jobId, reason):
        if not self._owns(accountId):
            self._deny("rejectCorrection")
            return "ERROR: Your session has expired."
        try:
            from .services import jobs as jobs_svc
            ok, result = jobs_svc.reject_correction(jobId, accountId, reason)
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("rejectCorrection failed")
            return "ERROR: Correction could not be rejected."

    @Slot(result="QVariantMap")
    def sweepTimers(self):
        try:
            from .services import timers
            return timers.sweep()
        except Exception:
            log.exception("sweepTimers failed")
            return {}

    # ------------------------------------------------------------------
    # Reviews
    # ------------------------------------------------------------------

    @Slot(str, int, result="QVariantMap")
    def canReview(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("canReview")
            return {"ok": False, "reason": "Session expired."}
        try:
            from .services import reviews as reviews_svc
            ok, reason = reviews_svc.can_review(jobId, accountId)
            return {"ok": ok, "reason": reason}
        except Exception:
            log.exception("canReview failed")
            return {"ok": False, "reason": "Could not check."}

    @Slot(str, int, int, str, result=str)
    def createReview(self, accountId, jobId, stars, comment):
        if not self._owns(accountId):
            self._deny("createReview")
            return "ERROR: Your session has expired."
        try:
            from .services import reviews as reviews_svc
            ok, result = reviews_svc.create_review(
                jobId, accountId, stars, comment or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("createReview failed")
            return "ERROR: Could not submit review."

    @Slot(str, int, int, str, result=str)
    def updateReview(self, accountId, reviewId, stars, comment):
        if not self._owns(accountId):
            self._deny("updateReview")
            return "ERROR: Your session has expired."
        try:
            from .services import reviews as reviews_svc
            ok, result = reviews_svc.update_review(
                reviewId, accountId, stars, comment or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("updateReview failed")
            return "ERROR: Could not update review."

    @Slot(str, int, result="QVariantMap")
    def getReviewForJob(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("getReviewForJob")
            return {}
        try:
            from .services import reviews as reviews_svc
            return reviews_svc.get_review_for_job(jobId, accountId)
        except Exception:
            log.exception("getReviewForJob failed")
            return {}

    @Slot(str, int, result="QVariantList")
    def listReviewsForJob(self, accountId, jobId):
        if not self._owns(accountId):
            self._deny("listReviewsForJob")
            return []
        try:
            from .services import reviews as reviews_svc
            return reviews_svc.list_reviews_for_job(jobId)
        except Exception:
            log.exception("listReviewsForJob failed")
            return []

    @Slot(str, result="QVariantList")
    def listReviewsReceived(self, accountId):
        if not self._owns(accountId):
            self._deny("listReviewsReceived")
            return []
        try:
            from .services import reviews as reviews_svc
            return reviews_svc.list_reviews_received(accountId)
        except Exception:
            log.exception("listReviewsReceived failed")
            return []

    @Slot(str, result="QVariantList")
    def listReviewsLeft(self, accountId):
        if not self._owns(accountId):
            self._deny("listReviewsLeft")
            return []
        try:
            from .services import reviews as reviews_svc
            return reviews_svc.list_reviews_left(accountId)
        except Exception:
            log.exception("listReviewsLeft failed")
            return []

    @Slot(str, result="QVariantMap")
    def averageForAccount(self, accountId):
        if not self._owns(accountId):
            self._deny("averageForAccount")
            return {"avg": 0.0, "count": 0}
        try:
            from .services import reviews as reviews_svc
            avg, n = reviews_svc.average_for_account(accountId)
            return {"avg": avg, "count": n}
        except Exception:
            log.exception("averageForAccount failed")
            return {"avg": 0.0, "count": 0}

    @Slot(str, int, str, result=str)
    def reportReview(self, accountId, reviewId, reason):
        if not self._owns(accountId):
            self._deny("reportReview")
            return "ERROR: Your session has expired."
        try:
            from .services import reviews as reviews_svc
            ok, result = reviews_svc.report_review(reviewId, accountId, reason or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("reportReview failed")
            return "ERROR: Could not report review."

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    @Slot(str, result="QVariantList")
    def listNotifications(self, accountId):
        if not self._owns(accountId):
            self._deny("listNotifications")
            return []
        try:
            from .services import notifications
            return notifications.list_for_account(accountId)
        except Exception:
            log.exception("listNotifications failed")
            return []

    @Slot(str, "QVariantList", result=int)
    def markNotificationsSeen(self, accountId, keys):
        if not self._owns(accountId):
            self._deny("markNotificationsSeen")
            return 0
        try:
            from .services import notifications
            return notifications.mark_seen(accountId, keys or [])
        except Exception:
            log.exception("markNotificationsSeen failed")
            return 0

    # ------------------------------------------------------------------
    # Provider services
    # ------------------------------------------------------------------

    @Slot(str, result="QVariantList")
    def listProviderServices(self, providerId):
        if not self._user_session_active():
            self._deny("listProviderServices")
            return []
        try:
            from .services import marketplace
            return marketplace.list_provider_services(providerId or "", include_inactive=False)
        except Exception:
            log.exception("listProviderServices failed")
            return []

    @Slot(str, result="QVariantList")
    def listMyServices(self, accountId):
        if not self._owns(accountId):
            self._deny("listMyServices")
            return []
        try:
            from .services import marketplace
            return marketplace.list_provider_services(accountId, include_inactive=True)
        except Exception:
            log.exception("listMyServices failed")
            return []

    @Slot(str, str, str, str, str, result=str)
    def addProviderService(self, accountId, category, title, description, rateText):
        if not self._owns(accountId):
            self._deny("addProviderService")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.add_provider_service(
                accountId, category or "", title or "",
                description or "", rateText or "")
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("addProviderService failed")
            return "ERROR: Service could not be added."

    @Slot(str, int, str, str, str, result=str)
    def updateProviderService(self, accountId, serviceId, title, description, rateText):
        if not self._owns(accountId):
            self._deny("updateProviderService")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.update_provider_service(
                int(serviceId), accountId, title or "",
                description or "", rateText or "")
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("updateProviderService failed")
            return "ERROR: Service could not be updated."

    @Slot(str, int, result=str)
    def deleteProviderService(self, accountId, serviceId):
        if not self._owns(accountId):
            self._deny("deleteProviderService")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.delete_provider_service(int(serviceId), accountId)
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("deleteProviderService failed")
            return "ERROR: Service could not be deleted."

    @Slot(str, int, result=str)
    def toggleProviderService(self, accountId, serviceId):
        if not self._owns(accountId):
            self._deny("toggleProviderService")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.toggle_provider_service(int(serviceId), accountId)
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("toggleProviderService failed")
            return "ERROR: Could not change visibility."

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @Slot(str, result="QVariantMap")
    def getMyAvailability(self, accountId):
        if not self._owns(accountId):
            self._deny("getMyAvailability")
            return {}
        try:
            from .services import marketplace
            return marketplace.get_provider_availability(accountId)
        except Exception:
            log.exception("getMyAvailability failed")
            return {}

    @Slot(str, str, str, str, result=str)
    def setMyAvailability(self, accountId, mode, availableAt, note):
        if not self._owns(accountId):
            self._deny("setMyAvailability")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.set_provider_availability(
                accountId, mode or "", availableAt or "", note or "")
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("setMyAvailability failed")
            return "ERROR: Could not update availability."

    # ------------------------------------------------------------------
    # Portfolio
    # ------------------------------------------------------------------

    @Slot(str, result="QVariantList")
    def listMyPortfolio(self, accountId):
        if not self._owns(accountId):
            self._deny("listMyPortfolio")
            return []
        try:
            from .services import marketplace
            return marketplace.portfolio_for_provider(accountId, include_hidden=True)
        except Exception:
            log.exception("listMyPortfolio failed")
            return []

    @Slot(str, result="QVariantList")
    def listProviderPortfolio(self, providerId):
        if not self._user_session_active():
            self._deny("listProviderPortfolio")
            return []
        try:
            from .services import marketplace
            return marketplace.portfolio_for_provider(providerId or "", include_hidden=False)
        except Exception:
            log.exception("listProviderPortfolio failed")
            return []

    @Slot(str, str, str, str, result=str)
    def addPortfolioItem(self, accountId, srcPath, title, description):
        if not self._owns(accountId):
            self._deny("addPortfolioItem")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.add_portfolio_item(
                accountId, srcPath or "", title or "", description or "")
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("addPortfolioItem failed")
            return "ERROR: Photo could not be added."

    @Slot(str, int, str, str, result=str)
    def updatePortfolioItem(self, accountId, itemId, title, description):
        if not self._owns(accountId):
            self._deny("updatePortfolioItem")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.update_portfolio_item(
                itemId, accountId, title or "", description or "")
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("updatePortfolioItem failed")
            return "ERROR: Photo could not be updated."

    @Slot(str, int, result=str)
    def deletePortfolioItem(self, accountId, itemId):
        if not self._owns(accountId):
            self._deny("deletePortfolioItem")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.delete_portfolio_item(itemId, accountId)
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("deletePortfolioItem failed")
            return "ERROR: Photo could not be deleted."

    @Slot(str, int, result=str)
    def togglePortfolioVisibility(self, accountId, itemId):
        if not self._owns(accountId):
            self._deny("togglePortfolioVisibility")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.toggle_portfolio_visibility(itemId, accountId)
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("togglePortfolioVisibility failed")
            return "ERROR: Could not change visibility."

    # ------------------------------------------------------------------
    # Saved providers
    # ------------------------------------------------------------------

    @Slot(str, str, result=bool)
    def isProviderSaved(self, accountId, providerId):
        if not self._owns(accountId):
            self._deny("isProviderSaved")
            return False
        try:
            from .services import marketplace
            return marketplace.is_saved(accountId, providerId or "")
        except Exception:
            log.exception("isProviderSaved failed")
            return False

    @Slot(str, str, result=str)
    def saveProvider(self, accountId, providerId):
        if not self._owns(accountId):
            self._deny("saveProvider")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.add_saved_provider(accountId, providerId or "")
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("saveProvider failed")
            return "ERROR: Could not save this provider."

    @Slot(str, str, result=str)
    def unsaveProvider(self, accountId, providerId):
        if not self._owns(accountId):
            self._deny("unsaveProvider")
            return "ERROR: Your session has expired."
        try:
            from .services import marketplace
            ok, msg = marketplace.remove_saved_provider(accountId, providerId or "")
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("unsaveProvider failed")
            return "ERROR: Could not remove this provider."

    @Slot(str, result="QVariantList")
    def listSavedProviders(self, accountId):
        if not self._owns(accountId):
            self._deny("listSavedProviders")
            return []
        try:
            from .services import marketplace
            return marketplace.list_saved_providers(accountId)
        except Exception:
            log.exception("listSavedProviders failed")
            return []

    # ------------------------------------------------------------------
    # Marketplace (read-only)
    # ------------------------------------------------------------------

    @Slot(str, str, str, str, result="QVariantList")
    def listProviders(self, accountId, family, area, search):
        if not self._owns(accountId):
            self._deny("listProviders")
            return []
        try:
            from .services import marketplace
            return marketplace.list_providers(
                family=family or "",
                area=area or "",
                search=search or "",
                limit=100,
                caller_account_id=accountId,
            )
        except Exception:
            log.exception("listProviders failed")
            return []

    @Slot(str, result="QVariantMap")
    def getProviderProfile(self, providerId):
        if not self._user_session_active():
            self._deny("getProviderProfile")
            return {}
        try:
            from .services import marketplace
            return marketplace.get_provider_profile(providerId or "")
        except Exception:
            log.exception("getProviderProfile failed")
            return {}

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------

    @Slot(str, result="QVariantList")
    def listConversations(self, accountId):
        if not self._owns(accountId):
            self._deny("listConversations")
            return []
        try:
            from .services import chat
            return chat.list_conversations(accountId)
        except Exception:
            log.exception("listConversations failed")
            return []

    @Slot(str, int, result="QVariantMap")
    def getConversation(self, accountId, conversationId):
        if not self._owns(accountId):
            self._deny("getConversation")
            return {}
        try:
            from .services import chat
            return chat.get_conversation(conversationId, accountId)
        except Exception:
            log.exception("getConversation failed")
            return {}

    @Slot(str, int, result="QVariantList")
    def listMessages(self, accountId, conversationId):
        if not self._owns(accountId):
            self._deny("listMessages")
            return []
        try:
            from .services import chat
            return chat.list_messages(conversationId, accountId)
        except Exception:
            log.exception("listMessages failed")
            return []

    @Slot(str, int, str, result=str)
    def sendMessage(self, accountId, conversationId, body):
        if not self._owns(accountId):
            self._deny("sendMessage")
            return "ERROR: Your session has expired."
        try:
            from .services import chat
            ok, result = chat.send_message(conversationId, accountId, body)
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("sendMessage failed")
            return "ERROR: Message could not be sent."

    @Slot(str, int, result=bool)
    def markConversationRead(self, accountId, conversationId):
        if not self._owns(accountId):
            self._deny("markConversationRead")
            return False
        try:
            from .services import chat
            return chat.mark_read(conversationId, accountId)
        except Exception:
            log.exception("markConversationRead failed")
            return False

    @Slot(str, result=int)
    def unreadCount(self, accountId):
        if not self._owns(accountId):
            self._deny("unreadCount")
            return 0
        try:
            from .services import chat
            return chat.unread_count(accountId)
        except Exception:
            log.exception("unreadCount failed")
            return 0

    @Slot(str, int, result=bool)
    def isChatLive(self, accountId, conversationId):
        if not self._owns(accountId):
            self._deny("isChatLive")
            return False
        try:
            from .services import chat
            return chat.is_chat_live(conversationId)
        except Exception:
            log.exception("isChatLive failed")
            return False

    # ------------------------------------------------------------------
    # Blocks
    # ------------------------------------------------------------------

    @Slot(str, str, result=bool)
    def isBlocked(self, accountId, otherAccountId):
        if not self._owns(accountId):
            self._deny("isBlocked")
            return False
        try:
            from .services import blocks as blocks_svc
            return blocks_svc.is_blocked(accountId, otherAccountId or "")
        except Exception:
            log.exception("isBlocked failed")
            return False

    @Slot(str, str, result=bool)
    def hasBlocked(self, accountId, otherAccountId):
        if not self._owns(accountId):
            self._deny("hasBlocked")
            return False
        try:
            from .services import blocks as blocks_svc
            return blocks_svc.has_blocked(accountId, otherAccountId or "")
        except Exception:
            log.exception("hasBlocked failed")
            return False

    @Slot(str, str, str, result=str)
    def blockUser(self, accountId, blockedId, reason):
        if not self._owns(accountId):
            self._deny("blockUser")
            return "ERROR: Your session has expired."
        try:
            from .services import blocks as blocks_svc
            ok, msg = blocks_svc.block_user(accountId, blockedId, reason)
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("blockUser failed")
            return "ERROR: Could not block this user."

    @Slot(str, str, result=str)
    def unblockUser(self, accountId, blockedId):
        if not self._owns(accountId):
            self._deny("unblockUser")
            return "ERROR: Your session has expired."
        try:
            from .services import blocks as blocks_svc
            ok, msg = blocks_svc.unblock_user(accountId, blockedId)
            return ("OK:" if ok else "ERROR: ") + msg
        except Exception:
            log.exception("unblockUser failed")
            return "ERROR: Could not unblock this user."

    @Slot(str, result="QVariantList")
    def listBlockedBy(self, accountId):
        if not self._owns(accountId):
            self._deny("listBlockedBy")
            return []
        try:
            from .services import blocks as blocks_svc
            return blocks_svc.list_blocked_by(accountId)
        except Exception:
            log.exception("listBlockedBy failed")
            return []

    # ------------------------------------------------------------------
    # Admin portal
    # ------------------------------------------------------------------

    @Slot(result=bool)
    def adminSetupRequired(self):
        try:
            from .services import admin as admin_svc
            return bool(admin_svc.ensure_admin_exists())
        except Exception:
            log.exception("adminSetupRequired failed")
            # Fail closed: do not expose setup UI if the DB status is unknown.
            return False

    @Slot(str, str, str, result=str)
    def adminCreateInitialAdmin(self, username, password, confirmation):
        try:
            from .services import admin as admin_svc
            ok, message = admin_svc.create_initial_admin(
                username or "", password or "", confirmation or "")
            return ("OK: " if ok else "ERROR: ") + message
        except Exception:
            log.exception("adminCreateInitialAdmin failed")
            return "ERROR: Initial administrator setup could not be completed."

    @Slot(str, str, result=str)
    def adminLogin(self, username, password):
        try:
            from .services import admin as admin_svc
            ok, result = admin_svc.admin_login(username, password)
            if not ok:
                return "ERROR: " + result
            self._admin_session.start(result)
            return "OK:" + result
        except Exception:
            log.exception("adminLogin failed")
            return "ERROR: Admin sign-in could not be completed."

    @Slot()
    def adminSignOut(self):
        self._admin_session.clear()

    @Slot(result="QVariantMap")
    def adminGetSelf(self):
        if not self._admin_session_active():
            return {}
        try:
            from .services import admin as admin_svc
            return admin_svc.get_admin(self._admin_session.identifier)
        except Exception:
            log.exception("adminGetSelf failed")
            return {}

    @Slot(result="QVariantMap")
    def adminDashboardStats(self):
        if not self._admin_session_active():
            return {}
        try:
            from .services import admin as admin_svc
            return admin_svc.get_dashboard_stats()
        except Exception:
            log.exception("adminDashboardStats failed")
            return {}

    @Slot(str, result="QVariantList")
    def adminListDisputes(self, adminId):
        if not self._owns_admin(adminId):
            self._deny("adminListDisputes")
            return []
        try:
            from .services import admin as admin_svc
            return admin_svc.list_open_disputes()
        except Exception:
            log.exception("adminListDisputes failed")
            return []

    @Slot(str, int, result="QVariantMap")
    def adminGetDisputeContext(self, adminId, disputeId):
        if not self._owns_admin(adminId):
            self._deny("adminGetDisputeContext")
            return {}
        try:
            from .services import admin as admin_svc
            result = admin_svc.get_dispute_context(int(disputeId))
            if result:
                job = result.get("job") or {}
                if job.get("client_account_id"):
                    admin_svc.mark_thread_read_by_admin(
                        int(disputeId), job["client_account_id"])
                if job.get("provider_account_id"):
                    admin_svc.mark_thread_read_by_admin(
                        int(disputeId), job["provider_account_id"])
            return result
        except Exception:
            log.exception("adminGetDisputeContext failed")
            return {}

    @Slot(str, int, result="QVariantMap")
    def adminGetDispute(self, adminId, disputeId):
        if not self._owns_admin(adminId):
            self._deny("adminGetDispute")
            return {}
        try:
            from .services import admin as admin_svc
            return admin_svc.get_dispute(int(disputeId))
        except Exception:
            log.exception("adminGetDispute failed")
            return {}

    @Slot(str, int, str, str, str, result=str)
    def adminPostDisputeMessage(self, adminId, disputeId, body, kind, target):
        if not self._owns_admin(adminId):
            self._deny("adminPostDisputeMessage")
            return "ERROR: Your admin session has expired."
        try:
            from .services import admin as admin_svc
            ok, result = admin_svc.post_dispute_message(
                adminId, int(disputeId), body or "",
                kind or "question", target or "both")
            return ("OK: " if ok else "ERROR: ") + result
        except Exception:
            log.exception("adminPostDisputeMessage failed")
            return "ERROR: Message could not be posted."

    @Slot(str, int, str, result=str)
    def adminHoldDispute(self, adminId, disputeId, reason):
        if not self._owns_admin(adminId):
            self._deny("adminHoldDispute")
            return "ERROR: Your admin session has expired."
        try:
            from .services import admin as admin_svc
            ok, result = admin_svc.hold_dispute(
                adminId, int(disputeId), reason or "")
            return ("OK: " if ok else "ERROR: ") + result
        except Exception:
            log.exception("adminHoldDispute failed")
            return "ERROR: Dispute could not be placed on hold."

    @Slot(str, int, str, str, result=str)
    def adminResolveDispute(self, adminId, disputeId, outcome, reason):
        if not self._owns_admin(adminId):
            self._deny("adminResolveDispute")
            return "ERROR: Your admin session has expired."
        try:
            from .services import admin as admin_svc
            ok, result = admin_svc.resolve_dispute(
                adminId, int(disputeId), outcome or "", reason or "")
            return ("OK: " if ok else "ERROR: ") + result
        except Exception:
            log.exception("adminResolveDispute failed")
            return "ERROR: Dispute could not be resolved."

    @Slot(str, result="QVariantList")
    def listMyAdminThreads(self, accountId):
        if not self._owns(accountId):
            self._deny("listMyAdminThreads")
            return []
        try:
            from .services import admin as admin_svc
            return admin_svc.list_party_thread(accountId)
        except Exception:
            log.exception("listMyAdminThreads failed")
            return []

    @Slot(str, int, str, str, result=str)
    def sendAdminThreadMessage(self, accountId, disputeId, body, evidencePath):
        if not self._owns(accountId):
            self._deny("sendAdminThreadMessage")
            return "ERROR: Your session has expired."
        try:
            from .services import admin as admin_svc
            ok, result = admin_svc.send_party_message(
                accountId, int(disputeId), body or "",
                evidence_path=evidencePath or "")
            return ("OK:" if ok else "ERROR: ") + result
        except Exception:
            log.exception("sendAdminThreadMessage failed")
            return "ERROR: Message could not be sent."

    @Slot(str, int, result=bool)
    def markAdminThreadRead(self, accountId, disputeId):
        if not self._owns(accountId):
            self._deny("markAdminThreadRead")
            return False
        try:
            from .services import admin as admin_svc
            return admin_svc.mark_thread_read(accountId, int(disputeId))
        except Exception:
            log.exception("markAdminThreadRead failed")
            return False

    @Slot(str, str, result="QVariantList")
    def adminListReports(self, adminId, kind):
        if not self._owns_admin(adminId):
            self._deny("adminListReports")
            return []
        try:
            from .services import admin as admin_svc
            return admin_svc.list_open_reports(kind or "")
        except Exception:
            log.exception("adminListReports failed")
            return []

    @Slot(str, int, str, result=str)
    def adminDismissReport(self, adminId, reportId, reason):
        if not self._owns_admin(adminId):
            self._deny("adminDismissReport")
            return "ERROR: Your admin session has expired."
        try:
            from .services import admin as admin_svc
            ok, result = admin_svc.dismiss_report(adminId, reportId, reason or "")
            return ("OK: " if ok else "ERROR: ") + result
        except Exception:
            log.exception("adminDismissReport failed")
            return "ERROR: Report could not be reviewed."

    @Slot(str, str, str, result="QVariantList")
    def adminSearchAccounts(self, adminId, query, role):
        if not self._owns_admin(adminId):
            self._deny("adminSearchAccounts")
            return []
        try:
            from .services import admin as admin_svc
            return admin_svc.search_accounts(query or "", role or "")
        except Exception:
            log.exception("adminSearchAccounts failed")
            return []

    @Slot(str, str, result="QVariantMap")
    def adminGetAccountDetail(self, adminId, accountId):
        if not self._owns_admin(adminId):
            self._deny("adminGetAccountDetail")
            return {}
        try:
            from .services import admin as admin_svc
            return admin_svc.get_account_detail(accountId or "")
        except Exception:
            log.exception("adminGetAccountDetail failed")
            return {}

    @Slot(str, str, str, str, result=str)
    def adminSetAccountStatus(self, adminId, accountId, newStatus, reason):
        if not self._owns_admin(adminId):
            self._deny("adminSetAccountStatus")
            return "ERROR: Your admin session has expired."
        try:
            from .services import admin as admin_svc
            ok, result = admin_svc.set_account_status(
                adminId, accountId, newStatus, reason or "")
            return ("OK: " if ok else "ERROR: ") + result
        except Exception:
            log.exception("adminSetAccountStatus failed")
            return "ERROR: Status could not be changed."

    @Slot(str, str, str, result=str)
    def adminIssuePasswordReset(self, adminId, accountId, reason):
        if not self._owns_admin(adminId):
            self._deny("adminIssuePasswordReset")
            return "ERROR: Your admin session has expired."
        try:
            from .services import admin as admin_svc
            ok, result = admin_svc.issue_password_reset(
                adminId, accountId, reason or "")
            if ok:
                return "OK:" + result
            return "ERROR: " + result
        except Exception:
            log.exception("adminIssuePasswordReset failed")
            return "ERROR: Password reset could not be issued."

    @Slot(str, int, result="QVariantList")
    def adminListActions(self, adminId, limit):
        if not self._owns_admin(adminId):
            self._deny("adminListActions")
            return []
        try:
            from .services import admin as admin_svc
            return admin_svc.list_admin_actions(int(limit) if limit else 200)
        except Exception:
            log.exception("adminListActions failed")
            return []

    @Slot(str, str, str, str, result=str)
    def adminChangeOwnPassword(self, adminId, current, newPassword, confirmation):
        if not self._owns_admin(adminId):
            self._deny("adminChangeOwnPassword")
            return "ERROR: Your admin session has expired."
        try:
            from .services import admin as admin_svc
            ok, msg = admin_svc.change_own_password(
                adminId, current or "", newPassword or "", confirmation or "")
            return ("OK: " if ok else "ERROR: ") + msg
        except Exception:
            log.exception("adminChangeOwnPassword failed")
            return "ERROR: Password could not be updated."

    @Slot(str, str, str, result=str)
    def adminChangeOwnUsername(self, adminId, newUsername, password):
        if not self._owns_admin(adminId):
            self._deny("adminChangeOwnUsername")
            return "ERROR: Your admin session has expired."
        try:
            from .services import admin as admin_svc
            ok, msg = admin_svc.change_own_username(
                adminId, newUsername or "", password or "")
            return ("OK: " if ok else "ERROR: ") + msg
        except Exception:
            log.exception("adminChangeOwnUsername failed")
            return "ERROR: Username could not be updated."

    @Slot(str, result=bool)
    def adminIsDefaultPassword(self, adminId):
        if not self._owns_admin(adminId):
            self._deny("adminIsDefaultPassword")
            return False
        try:
            from .services import admin as admin_svc
            return admin_svc.is_default_password(adminId)
        except Exception:
            log.exception("adminIsDefaultPassword failed")
            return False

    # ------------------------------------------------------------------
    # Static lists
    # ------------------------------------------------------------------

    @Slot(result="QVariantList")
    def serviceFamilies(self):
        return [{"key": k, "label": v} for k, v in categories.SERVICE_FAMILIES]

    @Slot(str, result="QVariantList")
    def categoriesForFamily(self, family):
        return categories.CATEGORIES.get(family, [])

    @Slot(result="QVariantList")
    def allCategories(self):
        out = []
        for family, cats in categories.CATEGORIES.items():
            for c in cats:
                out.append({"family": family, "category": c})
        return out

    @Slot(result="QVariantList")
    def listCustomServiceCategories(self):
        try:
            from .services import marketplace as market_svc
            return market_svc.list_custom_service_categories()
        except Exception:
            log.exception("listCustomServiceCategories failed")
            return []

    @Slot(result="QVariantList")
    def operatingAreas(self):
        return categories.OPERATING_AREAS

    @Slot(str, result="QVariantList")
    def incidentTypesForRole(self, role):
        if role == "provider":
            return db.INCIDENT_TYPES_PROVIDER
        return db.INCIDENT_TYPES_CLIENT