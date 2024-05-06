/**************************************************
 *  (C) 2024 Yuta Tokusashi, All Rights Reserved.
 **************************************************/

module pcap_parser();

typedef struct {
  bit [31:0] magic;
  bit [15:0] version_major;
  bit [15:0] version_minor;
  bit [31:0] thiszone;
  bit [31:0] sigfigs;
  bit [31:0] snaplen;
  bit [31:0] linktype;
} pcap_glob_hdr;

typedef struct {
  bit [31:0] tv_sec;
  bit [31:0] tv_usec;
  bit [31:0] caplen;
  bit [31:0] len;
} pcap_local_hdr;

localparam MAGIC_LIBPCAP = 32'hd4c3b2a1;
localparam DLT_EN10MB    = 32'h01000000;

localparam DEBUG_ENABLE  = 1'b1;
localparam DEBUG_DISABLE = 1'b0;

bit [31:0] snaplen_tmp;

task convert_to_axis(
  bit [7:0]packet[0:8191], 
  int size,
  output bit [511:0] tdata [],
  output bit [63:0]  tkeep [],
  output bit         tlast []
);
  bit [511:0] tdata_pack;
  bit [63+64:0] tkeep_tmp;

  automatic int flit_cnt = 0;
  automatic int j = 0;
  automatic int p = 0;
  automatic int d = 0;
  automatic int mod = 0;

  for (int j = 0; j < $ceil(size/64.0) ; j+=1) begin
    tdata = new[tdata.size() + 1](tdata);
    tkeep = new[tkeep.size() + 1](tkeep);
    tlast = new[tlast.size() + 1](tlast);
    mod = size % 64; 
	if ( mod + j*64 == size) begin
	  if (mod != 0)
	    d = mod;
      else 
	    d = 64;
	  tlast[flit_cnt] = 1;
	end
	else begin
	  d = 64;
	  tlast[flit_cnt] = 0;
	end
    tkeep_tmp = {64'h0, {64{1'b1}}};
    for (int i = 0; i < d; i+=1) begin
      tdata_pack[8*i +: 8] = packet[p];
      tkeep_tmp = tkeep_tmp << 1;
	  p += 1;
    end
	tdata[flit_cnt] = tdata_pack;
	tkeep[flit_cnt] = tkeep_tmp[127:64];
	$display("TDATA:0x%x", tdata[flit_cnt]);
	$display("TKEEP:0x%x", tkeep[flit_cnt]);
	$display("TLAST:0x%x", tlast[flit_cnt]);
	flit_cnt++;
  end

endtask

task read_pcap(
  string file,
  bit debug,
  output bit [511:0] tdata [],
  output bit [63:0]  tkeep [],
  output bit         tlast []
);

  bit [7:0] packet [0:8191];
  bit [7:0] data;
  bit [31:0] caplen_tmp;
  bit [31:0] len_tmp;

  //bit [511:0] tdata [];
  //bit [63:0]  tkeep [];
  //bit         tlast [];

  automatic int read_bytes = 0;
  automatic int pkt_count = 0;
  automatic integer fd = $fopen(file,"r");
  pcap_glob_hdr glob_hdr;
  pcap_local_hdr local_hdr;

  $fread(glob_hdr, fd);
  if (debug) begin
    $display("%p", glob_hdr);
    $display("glob_hdr.magic: 0x%x", glob_hdr.magic);
    $display("glob_hdr.major_version: 0x%x", glob_hdr.version_major);
    $display("glob_hdr.minor_version: 0x%x", glob_hdr.version_minor);
    $display("glob_hdr.snaplen: 0x%x", glob_hdr.snaplen);
    snaplen_tmp = {<<8{glob_hdr.snaplen}};
    $display("revised snaplen: 0x%x (%d)", snaplen_tmp, snaplen_tmp);
  end
  if (glob_hdr.magic != MAGIC_LIBPCAP) begin
    $display("Error: magic number is not supported.");
    return;
  end
  while(!$feof(fd)) begin
    $fread(local_hdr, fd);
	if($feof(fd) == 1) begin
	  return;
	end
	pkt_count += 1;
    caplen_tmp = {<<8{local_hdr.caplen}};
    len_tmp = {<<8{local_hdr.len}};
	//$display("%p", local_hdr);
	$display("Pkt[%d] captured len: %d Byte, len: %d Byte", pkt_count, caplen_tmp, len_tmp);
    while (read_bytes < caplen_tmp) begin
      $fread(data, fd);
	  packet[read_bytes] = data;
      read_bytes = read_bytes + 1;
    end
	//$display("%p", packet);
	read_bytes = 0;
	convert_to_axis(packet, caplen_tmp, tdata, tkeep, tlast);
  end

endtask

task write_pcap(
  string file,
  bit debug,
  bit [511:0] tdata [],
  bit [63:0]  tkeep [],
  bit         tlast []
);

  bit [7:0] data;
  bit [7:0] packet [0:8191];
  bit [511:0] tdata_tmp;
  bit [63:0] tkeep_tmp;
  pcap_glob_hdr glob_hdr;
  pcap_local_hdr local_hdr;
  automatic integer fd = $fopen(file,"w");
  automatic integer flit_cnt = 0;
  automatic integer pkt_pos = 0;

  glob_hdr.magic = MAGIC_LIBPCAP;
  glob_hdr.version_major = 16'h0200;
  glob_hdr.version_minor = 16'h0400;
  glob_hdr.thiszone = 16'h0;
  glob_hdr.sigfigs = 16'h0;
  glob_hdr.snaplen = 32'h00000400;
  glob_hdr.linktype = DLT_EN10MB;

  $fwrite(fd, glob_hdr);

  while(tlast.size != flit_cnt) begin
    while (tlast[flit_cnt]) begin
      tdata_tmp = tdata[flit_cnt];
      tkeep_tmp = tkeep[flit_cnt];
      for (int i = 0; i < 64; i++)  begin
        if (tkeep_tmp[i]) begin
          packet[pkt_pos++] = tdata_tmp[i*8 +: 8];
        end
      end
      flit_cnt++;
    end

    local_hdr.tv_sec  = 32'h0;
    local_hdr.tv_usec = 32'h0;
    local_hdr.caplen  = pkt_pos;
    local_hdr.len     = pkt_pos;
    
    $fwrite(fd, local_hdr);
	for (int i = 0; i < pkt_pos; i++) begin
	  data = packet[i];
      $fwrite(fd, data);
	end
  end

  $flocse(fd);

endtask

bit [511:0] tdata [];
bit [63:0]  tkeep [];
bit         tlast [];

//bit [511:0] tdata_out [];
//bit [63:0]  tkeep_out [];
//bit         tlast_out [];

initial begin
  read_pcap("f.pcap", DEBUG_ENABLE, tdata, tkeep, tlast);

  write_pcap("output.pcap", DEBUG_ENABLE, tdata, tkeep, tlast);

  $finish;
end 

endmodule
