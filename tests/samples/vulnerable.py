# tests/samples/vulnerable.py
import os
import pickle

def unsafe_command(user_input):
    # Vulnerability: Command injection
    os.system(f"echo {user_input}")
    
def unsafe_eval(expression):
    # Vulnerability: Code injection
    result = eval(expression)
    return result

def unsafe_deserialization(data):
    # Vulnerability: Insecure deserialization
    obj = pickle.loads(data)
    return obj

def complex_function(a, b, c, d, e):
    # High complexity function
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        return a + b + c + d + e
                    else:
                        return a + b + c + d
                else:
                    return a + b + c
            else:
                return a + b
        else:
            return a
    else:
        return 0
