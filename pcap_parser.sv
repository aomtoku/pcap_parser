/**************************************************
 *  (C) 2024 Yuta Tokusashi, All Rights Reserved.
 **************************************************/

module pcap_parser();

struct {
  bit [31:0] magic;
  bit [15:0] version_major;
  bit [15:0] version_minor;
  bit [31:0] thiszone;
  bit [31:0] sigfigs;
  bit [31:0] snaplen;
  bit [31:0] linktype;
} pcap_glob_hdr;

struct {
  bit [31:0] tv_sec;
  bit [31:0] tv_usec;
  bit [31:0] caplen;
  bit [31:0] len;
} pcap_local_hdr;

localparam DLT_EN10MB = 32'h01000000;
bit [31:0] snaplen_tmp;

task convert_to_axis(bit [7:0]packet[0:8191], int size);
  bit [511:0] tdata;
  bit [63:0]  tkeep;
  bit         tlast;
  bit [63+64:0] tkeep_tmp;
  automatic int j = 0;
  automatic int p = 0;
  automatic int d = 0;
  automatic int mod = 0;
  tkeep = 0;
  for (int j = 0; j < $ceil(size/64.0) ; j+=1) begin
    mod = size % 64; 
	if ( mod + j*64 == size) begin
	  if (mod != 0)
	    d = mod;
      else 
	    d = 64;
	  tlast = 1;
	end
	else begin
	  d = 64;
	  tlast = 0;
	end
    tkeep_tmp = {64'h0, {64{1'b1}}};
    for (int i = 0; i < d; i+=1) begin
      tdata[8*i +: 8] = packet[p];
      tkeep_tmp = tkeep_tmp << 1;
	  p += 1;
    end
	tkeep = tkeep_tmp[127:64];
	$display("TDATA:0x%x", tdata);
	$display("TKEEP:0x%x", tkeep);
	$display("TLAST:0x%x", tlast);
  end

endtask

task read_pcap(string file);

  bit [7:0] packet [0:8191];
  bit [7:0] data;
  bit [31:0] caplen_tmp;
  bit [31:0] len_tmp;
  automatic int read_bytes = 0;
  automatic int pkt_count = 0;
  automatic integer fd = $fopen(file,"r");
  $fread(pcap_glob_hdr, fd);
  $display("%p", pcap_glob_hdr);
  $display("0x%x", pcap_glob_hdr.magic);
  $display("0x%x", pcap_glob_hdr.snaplen);
  snaplen_tmp = {<<8{pcap_glob_hdr.snaplen}};
  $display("0x%x (%d)", snaplen_tmp, snaplen_tmp);
  if (pcap_glob_hdr.magic != 32'hd4c3b2a1) begin
    $display("Error: magic number is not supported.");
    return;
  end
  while(!$feof(fd)) begin
    $fread(pcap_local_hdr, fd);
	if($feof(fd) == 1) begin
	  return;
	end
	pkt_count += 1;
    caplen_tmp = {<<8{pcap_local_hdr.caplen}};
    len_tmp = {<<8{pcap_local_hdr.len}};
	//$display("%p", pcap_local_hdr);
	$display("Pkt[%d] captured len: %d Byte, len: %d Byte", pkt_count, caplen_tmp, len_tmp);
    while (read_bytes < caplen_tmp) begin
      $fread(data, fd);
	  packet[read_bytes] = data;
      read_bytes = read_bytes + 1;
    end
	//$display("%p", packet);
	read_bytes = 0;
	convert_to_axis(packet, caplen_tmp);
  end

endtask

task write_pcap(string file);

endtask

initial begin
  read_pcap("f.pcap");
  $finish;
end

endmodule
