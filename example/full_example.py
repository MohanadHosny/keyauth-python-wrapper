from keyauth import KeyAuth, get_hwid

def main() -> None:
    client = KeyAuth(
        "your app name",
        "your owner id",
        "your app secret",
        "your app version"
    )
    init_data = client.initialize()

    if not init_data.is_success:
        print(init_data.messsage)
        input()
        exit(1)
    
    print("""
1 - Login
2 - Register
3 - Upgrade
4 - Login via license key""")

    option = input("Option -> ")
    if option == "1":
        username = input("Input your username: ")
        password = input("Input your password: ")
        result = client.login(username, password)

        if result.is_success:
            print(result.message)
            # you can redirect to menu or smth you do it :D
        else:
            # Here prints the message from the keyauth server
            print(result.message)
    elif option == "2":
        username = input("Input your username: ")
        password = input("Input your password: ")
        license_key = input("Input your license key: ")
        result = client.register(username, password, license_key)

        if result.is_success:
            print(result.message)
            # you can redirect to menu or smth you do it :D
        else:
            # Here prints the message from the keyauth server
            print(result.message)
    elif option == "3":
        username = input("Input your username: ")
        upgrade_key = input("Input your upgrade key: ")
        result = client.upgrade(username, upgrade_key)

        if result.is_success:
            print(result.message)
            # you can redirect to menu or smth you do it :D
        else:
            # Here prints the message from the keyauth server
            print(result.message)
    elif option == "4":
        license_key = input("Input your license key (login): ")
        result = client.license_key(license_key)

        if result.is_success:
            print(result.message)
            # you can redirect to menu or smth you do it :D
        else:
            # Here prints the message from the keyauth server
            print(result.message)

if __name__ == "__main__":
    main()