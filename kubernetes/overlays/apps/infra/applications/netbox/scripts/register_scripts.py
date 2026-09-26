"""
Init script — registers NetBox custom script modules in the database.
Run via: manage.py shell < register_scripts.py
"""
import os

from extras.models import ScriptModule

SCRIPTS_DIR = "/opt/netbox/netbox/scripts"

# Remove any stale records with the wrong "scripts/" prefix
deleted, _ = ScriptModule.objects.filter(file_path__startswith="scripts/").delete()
if deleted:
    print(f"Removed {deleted} stale script module record(s) with wrong path prefix")

for filename in sorted(os.listdir(SCRIPTS_DIR)):
    if not filename.endswith(".py") or filename.startswith("_") or filename == "register_scripts.py":
        continue
    obj, created = ScriptModule.objects.get_or_create(file_path=filename)
    if created:
        print(f"Registered script module: {filename}")
    else:
        print(f"Already registered: {filename}")
