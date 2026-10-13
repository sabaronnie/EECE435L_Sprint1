"""Asset management logic. HTTP routes are defined in app.py."""

from database import assets
from database.logs import record_activity
from database.users import UserRepository
from errors import ApiError
import validation


def check_owner(owner_id):
    if UserRepository().by_id(owner_id) is None:
        raise ApiError("Asset owner does not exist")


def find_asset(asset_id):
    asset = assets.get_asset_by_id(asset_id)
    if asset is None:
        raise ApiError("Asset not found", 404)
    return asset


def list_assets():
    return assets.get_assets()


def get_asset(asset_id):
    asset = find_asset(asset_id)
    asset.update(assets.get_asset_links(asset_id))
    return asset


def create_asset(data, actor):
    data = validation.asset_creation(data)
    check_owner(data["owner_id"])
    asset = assets.insert_asset(data)
    record_activity(actor, "ASSET_CREATED", f"Created asset {asset['asset_id']}: {asset['asset_name']}",
                    related_service="Asset Management")
    return asset


def update_asset(asset_id, data, actor):
    data = validation.asset_update(data)
    find_asset(asset_id)
    check_owner(data["owner_id"])
    asset = assets.update_asset(asset_id, data)
    record_activity(actor, "ASSET_UPDATED", f"Updated asset {asset_id}: {asset['asset_name']}",
                    related_service="Asset Management")
    return asset


def delete_asset(asset_id, actor):
    asset = find_asset(asset_id)
    if not assets.delete_asset(asset_id):
        raise ApiError("Asset not found", 404)
    record_activity(actor, "ASSET_DELETED", f"Deleted asset {asset_id}: {asset['asset_name']}",
                    related_service="Asset Management")
