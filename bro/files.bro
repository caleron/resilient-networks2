#
# RN Aufgabe 2.2.1 Files 
# 

event file_sniff(f:fa_file,meta:fa_metadata){
    
#Initialisieren der zwei Variablen
    local ftype = "";
    local mime = "";

	if (meta?$mime_type){

	#Spaltet den String (//)
      	ftype = split_string(meta$mime_type, /\//)[1];
       	mime = meta$mime_type;
    	}

	local fname = fmt("%s-%s.%s", f$source, f$id, ftype);
	
	#Wie auf https://www.bro.org/bro-exchange-2013/exercises/faf.html beschrieben, unter 
	#Part 2&3, wird hier der "extraction" analyzer verwendet, um das File zu analysieren,
	#welches hier angegeben wird
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT,[$extract_filename=fname]);
	local source_ip: addr;
   	local dest_ip: addr;
   	local url = "";
	
	#Prüfen, ob es sich um eine valide Verbindung haltet
    	for (connection_id in f$conns){
      	
        source_ip = connection_id$orig_h;
        dest_ip = connection_id$resp_h;
        if (f$conns[connection_id]?$http)
	#Speichern der URL, egal welche HTTP reply, gesehen in Network Forensics von Ric Messier
            url = f$conns[connection_id]$http$uri;
    	}

	#Konsolenausgabe der gesammelten Daten in einem formatierten String 
	#Zunächst Typ, FileId, FileSource, Source, Destination und URL	
    	print fmt("%s %s %s %s %s %s" ,$file_type=mime, $file_id=f$id, $file_source=f$source, $source_ip=source_ip, $destination_ip=dest_ip, $download_url=url);

}


