import socket
print("|================================|")
print("| SELECT AN OPERATION TO PERFORM |")
print("|================================|")
print("         ↆ")
print("1. Scan Single IP")
print("2. Scan Range of IPs")

choice = int(input("Enter a number from above: "))

def scan_port(target, port):
    with socket.socket() as s:
        s.settimeout(1)
        result = s.connect_ex((target, port))
        if result != 0:
            print(f"Port {port} is closed.")
        elif port in whitelist:
            print(f"Port {port} is open on IP {target} and is in the whitelist")

if choice == 1:
    singleip = input("Enter target IP address: ")
    print("Enter port ranges, First port and Last port(exclusive).")
    First_port = int(input("Enter First port: "))
    Last_port = int(input("Enter Last port: "))

    target = singleip
    print("Scanning:", target)
    whitelist = [22, 80, 443, 8080]

    try:
        for port in range(First_port, Last_port):
            scan_port(target, port)
    except Exception as e:
        print(f"An error occurred: {e}")

else:
    firstip = input("Enter first IP: ")
    lastip = input("Enter last IP: ")
    print("Enter port ranges, First port and Last port(exclusive).")
    First_port = int(input("Enter First port: "))
    Last_port = int(input("Enter Last port: "))

    f = firstip.rfind('.') + 1
    flength = len(firstip)
    first = int(firstip[f:flength])

    l = lastip.rfind('.') + 1
    llength = len(lastip)
    last = int(lastip[l:llength])

    for ip in range(first, last + 1):
        target = firstip[0:f] + str(ip)
        print("Scanning:", target)
        whitelist = [22, 80, 443, 8080]

        try:
            for port in range(First_port, Last_port):
                scan_port(target, port)
        except Exception as e:
            print(f"An error occurred: {e}")
