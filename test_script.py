def login():
    # Hardcoded secret test
    password = "supersecretpassword123"
    api_key = "sk_test_12345"
    print(f"Logging in with {password} and {api_key}")

def process_data(user_data):
    # Compliance test
    rut = user_data.get("rut")
    print("Processing user rut:", rut)

def simulate_crash():
    print("About to crash...")
    x = 1 / 0  # ZeroDivisionError

if __name__ == "__main__":
    login()
    process_data({"rut": "12345678-9"})
    simulate_crash()
