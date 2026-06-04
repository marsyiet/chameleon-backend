PERMISSIONS = {

    "super_admin": [
        "*"
    ],

    "admin": [

        "organization.read",
        "organization.update",
        "organization.create",
        "organization.delete",

        "user.create",
        "user.read",
        "user.update",
        "user.delete",
        "user.unlock",

        "user.disable",
        "user.enable",

        "user.change_role",

        "user.unlock",
        "user.reset_password",
        
        "scan.create",
        "scan.read",
        "scan.update",
        "scan.delete",
        
        "asset.create",
        "asset.read",
        "asset.update",
        "asset.delete"
        
    ],

    "analyst": [

        "organization.read",

        "user.read",
    ],

    "viewer": [

        "organization.read",

        "user.read",
    ]
}