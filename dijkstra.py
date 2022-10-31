import sys
import json
import math  # If you want to use math.inf for infinity


def ipv4_to_value(ipv4_addr):
    """
    Convert a dots-and-numbers IP address to a single numeric value.
    Example:
    There is only one return value, but it is shown here in 3 bases.
    ipv4_addr: "255.255.0.0"
    return:    0xffff0000 0b11111111111111110000000000000000 4294901760
    ipv4_addr: "1.2.3.4"
    return:    0x01020304 0b00000001000000100000001100000100 16909060
    """
    sections = ipv4_addr.split(".")
    result = 0
    num = 24
    for part in sections:
        result = (int(part) << num) | result
        num = num - 8
    return result


def set_bit(num, digit):
    return num | (1 << digit)


def set_bits(num, begin, end):
    for i in range(begin, end):
        num = set_bit(num, i)
    return num


def get_subnet_mask_value(slash):
    """
    Given a subnet mask in slash notation, return the value of the mask
    as a single number. The input can contain an IP address optionally,
    but that part should be discarded.
    Example:
    There is only one return value, but it is shown here in 3 bases.
    slash:  "/16"
    return: 0xffff0000 0b11111111 11111111 00000000 00000000 4294901760
    slash:  "10.20.30.40/23"
    return: 0xfffffe00 0b11111111111111111111111000000000 4294966784
    """
    begin = 32 - int(slash.split("/")[-1])
    end = 32
    return set_bits(0, begin, end)


def ips_same_subnet(ip1, ip2, slash):
    """
    Given two dots-and-numbers IP addresses and a subnet mask in slash
    notataion, return true if the two IP addresses are on the same
    subnet.
    FOR FULL CREDIT: this must use your get_subnet_mask_value() and
    ipv4_to_value() functions. Don't do it with pure string
    manipulation.
    This needs to work with any subnet from /1 to /31
    Example:
    ip1:    "10.23.121.17"
    ip2:    "10.23.121.225"
    slash:  "/23"
    return: True

    ip1:    "10.23.230.22"
    ip2:    "10.24.121.225"
    slash:  "/16"
    return: False
    """
    mask = get_subnet_mask_value(slash)
    ip1_value = ipv4_to_value(ip1)
    ip2_value = ipv4_to_value(ip2)
    return ip1_value & mask == ip2_value & mask


def find_router_for_ip(routers, ip):
    """
    Search a dictionary of routers (keyed by router IP) to find which
    router belongs to the same subnet as the given IP.
    Return None if no routers is on the same subnet as the given IP.
    FOR FULL CREDIT: you must do this by calling your ips_same_subnet()
    function.
    Example:
    [Note there will be more data in the routers dictionary than is
    shown here--it can be ignored for this function.]
    routers: {
        "1.2.3.1": {
            "netmask": "/24"
        },
        "1.2.4.1": {
            "netmask": "/24"
        }
    }
    ip: "1.2.3.5"
    return: "1.2.3.1"
    routers: {
        "1.2.3.1": {
            "netmask": "/24"
        },
        "1.2.4.1": {
            "netmask": "/24"
        }
    }
    ip: "1.2.5.6"
    return: None
    """
    for router_ip, router in routers.items():
        if ips_same_subnet(ip, router_ip, router["netmask"]):
            return router_ip


def dijkstras_shortest_path(routers, src_ip, dest_ip):
    """
    This function takes a dictionary representing the network, a source
    IP, and a destination IP, and returns a list with all the routers
    along the shortest path.

    The source and destination IPs are **not** included in this path.

    Note that the source IP and destination IP will probably not be
    routers! They will be on the same subnet as the router. You'll have
    to search the routers to find the one on the same subnet as the
    source IP. Same for the destination IP. [Hint: make use of your
    find_router_for_ip() function from the last project!]

    The dictionary keys are router IPs, and the values are dictionaries
    with a bunch of information, including the routers that are directly
    connected to the key.

    This partial example shows that router `10.31.98.1` is connected to
    three other routers: `10.34.166.1`, `10.34.194.1`, and `10.34.46.1`:

    {
        "10.34.98.1": {
            "connections": {
                "10.34.166.1": {
                    "netmask": "/24",
                    "interface": "en0",
                    "ad": 70
                },
                "10.34.194.1": {
                    "netmask": "/24",
                    "interface": "en1",
                    "ad": 93
                },
                "10.34.46.1": {
                    "netmask": "/24",
                    "interface": "en2",
                    "ad": 64
                }
            },
            "netmask": "/24",
            "if_count": 3,
            "if_prefix": "en"
        },
        ...

    The "ad" (Administrative Distance) field is the edge weight for that
    connection.

    **Strong recommendation**: make functions to do subtasks within this
    function. Having it all built as a single wall of code is a recipe
    for madness.
    """
    to_visit = set()
    distance = {}
    parent = {}
    src_ip = find_router_for_ip(routers, src_ip)
    for router in routers:
        parent[router] = None
        distance[router] = math.inf
        to_visit.add(router)
    distance[src_ip] = 0

    while to_visit:
        current = min(to_visit, key=distance.get)
        to_visit.remove(current)
        for neighbor in routers[find_router_for_ip(routers, current)]["connections"]:
            if neighbor in to_visit:
                alt = distance[current] + routers[current]["connections"][neighbor]["ad"]
                if alt < distance[neighbor]:
                    distance[neighbor] = alt
                    parent[neighbor] = current

    dest_ip = find_router_for_ip(routers, dest_ip)
    current = dest_ip
    path = []
    while current != src_ip:
        path.append(current)
        current = parent[current]
    if path:
        path.append(current)
        path.reverse()
    return path


#------------------------------
# DO NOT MODIFY BELOW THIS LINE
#------------------------------
def read_routers(file_name):
    with open(file_name) as fp:
        data = fp.read()

    return json.loads(data)

def find_routes(routers, src_dest_pairs):
    for src_ip, dest_ip in src_dest_pairs:
        path = dijkstras_shortest_path(routers, src_ip, dest_ip)
        print(f"{src_ip:>15s} -> {dest_ip:<15s}  {repr(path)}")


def usage():
    print("usage: dijkstra.py infile.json", file=sys.stderr)

def main(argv):
    try:
        router_file_name = argv[1]
    except:
        usage()
        return 1

    json_data = read_routers(router_file_name)

    routers = json_data["routers"]
    routes = json_data["src-dest"]

    find_routes(routers, routes)


def test():
    json_data = read_routers("example1.json")
    routers = json_data["routers"]
    routes = json_data["src-dest"]

    shortest_path = ""
    for src_ip, dest_ip in routes:
        path = dijkstras_shortest_path(routers, src_ip, dest_ip)
        shortest_path += f"{src_ip:>15s} -> {dest_ip:<15s}  {repr(path)}\n"
    expected = ""
    with open("example1_output.txt") as fp:
        expected += fp.read()

    for i in range(len(shortest_path.split("\n"))):
        expected_path = expected.split("\n")[i]
        actual_path = shortest_path.split("\n")[i]
        assert expected_path == actual_path
        print("Test with output: {} \033[92mPassed\033[0m".format(expected_path))

    assert shortest_path == expected
    print("\033[92mAll tests passed\033[0m")

if __name__ == "__main__":
    sys.exit(main(sys.argv))
