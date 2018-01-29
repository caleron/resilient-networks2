#
# RN Aufgabe 2.2.2 Hardcoded IP addresses
# 

#Tables for DNS queries, and addresses as suggested by David Hoelzer
global dns_queries: table[addr] of addr;
global dns_query_quelle: table[addr] of addr;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    dns_query_quelle[c$id$orig_h] = c$id$resp_h;
}

#Track DNS addresses lookup responses, see https://stackoverflow.com/questions/47928298/bro-script-hardcoded-ip-#addresses 
#Event is generated for A-type DNS replies. Bro analyzes UDP and TCP DNS sessions
event dns_A_reply(c: connection, msg: dns_msg, ans:  dns_answer, a: addr) {
	dns_queries[c$id$orig_h] = a;
}

#Event is generated when seeing a SYN-ACK packet from the responder in a TCP handshake, as seen on the bro documentation pages www.bro.org/sphinx/scripts
event connection_established(c: connection) {
	local quelle: addr = c$id$orig_h;
	local senke: addr = c$id$resp_h;
	
	#Check if the address is in the tables of addresses as seen on stackoverflow and print results
	if (quelle !in dns_query_quelle || quelle in dns_queries && dns_queries[quelle] != c$id$resp_h) {
        local rec = [$source_ip=c$id$orig_h, $source_port=c$id$orig_p, $destination_ip=c$id$resp_h, $destination_port=c$id$resp_p];
        print(rec);
    	}
}
