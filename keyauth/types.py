from typing import NamedTuple, List

class Subscription(NamedTuple):
    level: str
    expiry: str # for some reason the api returns str lmao, tho you can parse it

class InitializeResult(NamedTuple):
    is_success: bool = False
    message: str = "Initialized"

class KeyAuthResult(NamedTuple):
    is_success: bool = False
    message: str = ""

class RegisterResult(NamedTuple):
    subscriptions: List[Subscription] = []
    register_ip: str = ""

    is_success: bool = False
    message: str = ""