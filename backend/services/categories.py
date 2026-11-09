"""Service families and categories. Static data — changes require code edits."""


SERVICE_FAMILIES = [
    ("home",     "Home Services"),
    ("personal", "Personal Services"),
]


CATEGORIES = {
    "home": [
        "Plumbing",
        "Electrical",
        "Cleaning",
        "Carpentry",
        "Painting",
        "Appliance Repair",
        "Gardening",
        "Moving",
    ],
    "personal": [
        "Hair",
        "Makeup",
        "Tailoring",
        "Spa",
        "Photography",
    ],
}


# Default timer windows per category.
# (mutual_completion_hours, hard_timeout_hours)
TIMERS = {
    "Cleaning":          (1,  6),
    "Plumbing":          (4, 24),
    "Electrical":        (4, 24),
    "Appliance Repair":  (4, 24),
    "Carpentry":        (24, 24 * 7),
    "Painting":         (24, 24 * 7),
    "Gardening":        (24, 24 * 7),
    "Moving":           (24, 24 * 7),
    "Hair":              (1,  6),
    "Makeup":            (1,  6),
    "Tailoring":        (24, 24 * 7),
    "Spa":              (24, 24 * 7),
    "Photography":      (24, 24 * 7),
}

DEFAULT_TIMERS = (4, 24)


OPERATING_AREAS = [
    "Nairobi CBD",
    "Westlands",
    "Rongai",
    "Kitengela",
    "Athi River",
    "Kiambu",
    "Ngong",
    "Ruaka",
    "Other",
]


# Search synonyms — seed data for the search_synonyms table.
SYNONYMS = [
    # Plumbing
    ("pipe", "Plumbing"), ("pipes", "Plumbing"), ("tap", "Plumbing"),
    ("taps", "Plumbing"), ("leak", "Plumbing"), ("leaking", "Plumbing"),
    ("faucet", "Plumbing"), ("drain", "Plumbing"), ("toilet", "Plumbing"),
    ("sink", "Plumbing"), ("shower", "Plumbing"), ("water", "Plumbing"),
    # Electrical
    ("power", "Electrical"), ("electricity", "Electrical"),
    ("socket", "Electrical"), ("wiring", "Electrical"),
    ("light", "Electrical"), ("lights", "Electrical"),
    ("bulb", "Electrical"), ("blackout", "Electrical"),
    ("switch", "Electrical"), ("fuse", "Electrical"),
    # Cleaning
    ("clean", "Cleaning"), ("cleaning", "Cleaning"),
    ("housekeeping", "Cleaning"), ("maid", "Cleaning"),
    ("laundry", "Cleaning"), ("washing", "Cleaning"),
    # Carpentry
    ("wood", "Carpentry"), ("furniture", "Carpentry"),
    ("cabinet", "Carpentry"), ("door", "Carpentry"),
    ("wardrobe", "Carpentry"), ("bed", "Carpentry"),
    # Painting
    ("paint", "Painting"), ("painting", "Painting"),
    ("wall", "Painting"), ("decor", "Painting"),
    # Appliance Repair
    ("fridge", "Appliance Repair"), ("refrigerator", "Appliance Repair"),
    ("washing machine", "Appliance Repair"), ("cooker", "Appliance Repair"),
    ("oven", "Appliance Repair"), ("microwave", "Appliance Repair"),
    ("tv", "Appliance Repair"), ("appliance", "Appliance Repair"),
    # Gardening
    ("garden", "Gardening"), ("lawn", "Gardening"),
    ("mow", "Gardening"), ("mowing", "Gardening"),
    ("plants", "Gardening"), ("trees", "Gardening"),
    # Moving
    ("move", "Moving"), ("moving", "Moving"),
    ("relocate", "Moving"), ("relocation", "Moving"),
    ("transport", "Moving"), ("carry", "Moving"),
    # Hair
    ("braid", "Hair"), ("braids", "Hair"), ("weave", "Hair"),
    ("wig", "Hair"), ("barber", "Hair"), ("salon", "Hair"),
    ("hairstyle", "Hair"), ("haircut", "Hair"),
    # Makeup
    ("makeup", "Makeup"), ("bridal", "Makeup"),
    ("glam", "Makeup"), ("cosmetics", "Makeup"),
    # Tailoring
    ("tailor", "Tailoring"), ("sew", "Tailoring"),
    ("sewing", "Tailoring"), ("dress", "Tailoring"),
    ("alteration", "Tailoring"), ("clothes", "Tailoring"),
    # Spa
    ("spa", "Spa"), ("massage", "Spa"),
    ("facial", "Spa"), ("manicure", "Spa"),
    ("pedicure", "Spa"), ("relax", "Spa"),
    # Photography
    ("photo", "Photography"), ("photos", "Photography"),
    ("photography", "Photography"), ("camera", "Photography"),
    ("shoot", "Photography"), ("videography", "Photography"),
]