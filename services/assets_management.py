"""Asset management logic. HTTP routes are defined in app.py."""

from database import assets
from database.logs import record_activity
from database.users import UserRepository
from errors import ApiError
import validation


def check_owner(owner_id):
    if UserRepository().by_id(owner_id) is None:
        raise ApiError("Asset owner does not exist")


def create_asset(data, actor):
    data = validation.asset_creation(data)
    check_owner(data["owner_id"])
    asset = assets.insert_asset(data)
    record_activity(actor, "ASSET_CREATED", f"Created asset {asset['asset_id']}: {asset['asset_name']}",
                    related_service="Asset Management")
    return asset
