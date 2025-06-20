from monolith import get_customer_balance

def test_existing_customer():
    assert get_customer_balance("cust001") == 150.75

def test_zero_balance():
    assert get_customer_balance("cust002") == 0.00

def test_unknown_customer():
    assert get_customer_balance("unknown") is None
