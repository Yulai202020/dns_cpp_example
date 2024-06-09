CPP_FLAGS = -lcares

check_ip:
	g++ check_ip.cpp -o check_ip $(CPP_FLAGS)
dns:
	g++ dns.cpp -o dns $(CPP_FLAGS)
get_ips:
	g++ get_ips.cpp -o get_ips $(CPP_FLAGS)
