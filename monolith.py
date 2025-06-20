def get_customer_balance(customer_id):
    # Simulating a database lookup
    dummy_data = {
        "cust001": 150.75,
        "cust002": 0.00,
        "cust003": -20.50,
    }
    return dummy_data.get(customer_id, None)
