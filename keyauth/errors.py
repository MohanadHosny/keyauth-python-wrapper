class KeyAuthException(Exception):
    def __init__(self, message):
        super().__init__(message)
        
class InvalidApplicationInformation(KeyAuthException):
    """Long text is secret short text is ownerid. Name is supposed to be app name not username."""
    pass

class ApplicationDoesntExist(KeyAuthException):
    """The application doesn't exist in keyauth."""
    pass