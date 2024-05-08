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


bit [7:0] file_hdr [23:0] = {
  8'h00,8'h00,8'h00,8'h00,
  8'h00,8'h00,8'h00,8'h00,
  8'h00,8'h00,8'h00,8'h00,
  8'h00,8'h00,8'h00,8'h00,
  8'h00,8'h00,8'h00,8'h00,
  8'h00,8'h00,8'h00,8'h00
};

bit [7:0] pcap_hdr [15:0] = {
  8'h00,8'h00,8'h00,8'h00,
  8'h00,8'h00,8'h00,8'h00,
  8'h00,8'h00,8'h00,8'h00,
  8'h00,8'h00,8'h00,8'h00
};

localparam MAGIC_LIBPCAP = 32'hd4c3b2a1;
localparam DLT_EN10MB    = 32'h01000000;

localparam DEBUG_ENABLE  = 1'b1;
localparam DEBUG_DISABLE = 1'b0;


parameter TDATA_WIDTH  = 512; 
parameter PKT_MTU_BYTE = 8192; 

bit [31:0] snaplen_tmp;

task automatic convert_to_axis(
  ref bit                  [7:0] packet [0:PKT_MTU_BYTE-1],
  bit                            debug,
  bit [31:0]                     size,
  output bit   [TDATA_WIDTH-1:0] tdata [],
  output bit [TDATA_WIDTH/8-1:0] tkeep [],
  output bit                     tlast []
);

  bit [TDATA_WIDTH-1:0] tdata_pack;
  bit [TDATA_WIDTH/8+TDATA_WIDTH/8-1:0] tkeep_tmp;

  automatic int flit_cnt = 0;
  automatic int j = 0;
  automatic int p = 0;
  automatic int d = 0;
  automatic int mod = 0;

  for (int j = 0; j < $ceil(size/64.0) ; j+=1) begin
    tdata = new[tdata.size() + 1](tdata);
    tkeep = new[tkeep.size() + 1](tkeep);
    tlast = new[tlast.size() + 1](tlast);
    mod = size % (TDATA_WIDTH/8); 
    if ( mod + j*(TDATA_WIDTH/8) == size) begin
      if (mod != 0)
        d = mod;
      else 
        d = TDATA_WIDTH/8;
      tlast[flit_cnt] = 1;
    end
    else begin
      d = TDATA_WIDTH/8;
      tlast[flit_cnt] = 0;
    end
    tkeep_tmp = {{(TDATA_WIDTH/8){1'b0}}, {(TDATA_WIDTH/8){1'b1}}};
	tdata_pack = 'h0;
    for (int i = 0; i < d; i+=1) begin
      tdata_pack[8*i +: 8] = packet[p];
      tkeep_tmp = tkeep_tmp << 1;
      p += 1;
    end
    tdata[flit_cnt] = tdata_pack;
    tkeep[flit_cnt] = tkeep_tmp[(TDATA_WIDTH/8)*2-1:(TDATA_WIDTH/8)];
    if (debug)
      $display("[CV] [%4d] TDATA:0x%x TKEEP:0x%x TLAST:0x%x", flit_cnt, tdata[flit_cnt], tkeep[flit_cnt], tlast[flit_cnt]);
    flit_cnt++;
  end

endtask

task read_pcap(
  string                         file,
  bit                            debug,
  output bit [TDATA_WIDTH-1:0]   tdata [],
  output bit [TDATA_WIDTH/8-1:0] tkeep [],
  output bit                     tlast []
);

  bit [7:0] packet [0:PKT_MTU_BYTE-1];
  bit [7:0] data;
  bit [31:0] caplen_tmp;
  bit [31:0] len_tmp;

  bit [TDATA_WIDTH-1:0]   tdata_f [];
  bit [TDATA_WIDTH/8-1:0] tkeep_f [];
  bit                     tlast_f [];

  automatic int read_bytes = 0;
  automatic int pkt_count = 0;
  automatic int f_count = 0;
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
    if (debug)
      $display("Pkt[%d] captured len: %d Byte, len: %d Byte", pkt_count, caplen_tmp, len_tmp);
    while (read_bytes < caplen_tmp) begin
      $fread(data, fd);
      packet[read_bytes] = data;
      read_bytes = read_bytes + 1;
    end
    read_bytes = 0;
    convert_to_axis(packet, debug, caplen_tmp, tdata_f, tkeep_f, tlast_f);
    
    tdata = new[tdata.size() + tdata_f.size()](tdata);
    tkeep = new[tkeep.size() + tkeep_f.size()](tkeep);
    tlast = new[tlast.size() + tlast_f.size()](tlast);

    for  (int i = 0; i < tdata_f.size(); i++) begin
      tdata[f_count] = tdata_f[i];
      tkeep[f_count] = tkeep_f[i];
      tlast[f_count] = tlast_f[i];
      f_count++;
    end
  end

endtask

task automatic write_pcap(
  string                      file,
  bit                         debug,
  ref bit [TDATA_WIDTH-1:0]   tdata [],
  ref bit [TDATA_WIDTH/8-1:0] tkeep [],
  ref bit                     tlast []
);

  bit [7:0] data;
  bit [7:0] packet [0:PKT_MTU_BYTE-1];
  bit [TDATA_WIDTH-1:0] tdata_tmp;
  bit [TDATA_WIDTH/8-1:0] tkeep_tmp;
  pcap_glob_hdr glob_hdr;
  pcap_local_hdr local_hdr;
  automatic integer fd = $fopen(file,"wb");
  automatic integer flit_cnt = 0;
  automatic integer pkt_pos = 0;

  // Writing Global Header
  glob_hdr.magic         = MAGIC_LIBPCAP;
  glob_hdr.version_major = 16'h0200;
  glob_hdr.version_minor = 16'h0400;
  glob_hdr.thiszone      = 32'h0;
  glob_hdr.sigfigs       = 32'h0;
  glob_hdr.snaplen       = 32'h00000400;
  glob_hdr.linktype      = DLT_EN10MB;

  for (int i = 0; i < 4; i++)
    file_hdr[20+i] = glob_hdr.magic[8*i +: 8];
  for (int i = 0; i < 2; i++)
    file_hdr[i+18] = glob_hdr.version_major[8*i +: 8];
  for (int i = 0; i < 2; i++)
    file_hdr[i+16] = glob_hdr.version_minor[8*i +: 8];
  for (int i = 0; i < 4; i++)
    file_hdr[i+12] = glob_hdr.thiszone[8*i +: 8];
  for (int i = 0; i < 4; i++)
    file_hdr[i+8] = glob_hdr.sigfigs[8*i +: 8];
  for (int i = 0; i < 4; i++)
    file_hdr[i+4] = glob_hdr.snaplen[8*i +: 8];
  for (int i = 0; i < 4; i++)
    file_hdr[i] = glob_hdr.linktype[8*i +: 8];
  foreach(file_hdr[i]) $fwrite(fd,"%c",file_hdr[i]);

  if (debug)
    $display("[WR] tlast.size: %d, tkeep.size: %d, tdata.size: %d", tlast.size, tkeep.size, tdata.size);
  while(tlast.size != flit_cnt) begin
    if (debug)
      $display("[WR] [%4d] TDATA:0x%x TKEEP:0x%x TLAST:0x%x", flit_cnt, tdata[flit_cnt], tkeep[flit_cnt], tlast[flit_cnt]);
    tdata_tmp = tdata[flit_cnt];
    tkeep_tmp = tkeep[flit_cnt];
    for (int i = 0; i < TDATA_WIDTH/8; i++)  begin
      if (tkeep_tmp[i]) begin
        packet[pkt_pos++] = tdata_tmp[i*8 +: 8];
      end
    end

    if (tlast[flit_cnt]) begin
      // Writing libpcap local header
      local_hdr.tv_sec  = 32'hfa;
      local_hdr.tv_usec = 32'h12345678;
      local_hdr.caplen  = {<<8{pkt_pos}};
      local_hdr.len     = {<<8{pkt_pos}};

      for (int i = 0; i < 4; i++)
        pcap_hdr[i+12] = local_hdr.tv_sec[8*i +: 8];
      for (int i = 0; i < 4; i++)
        pcap_hdr[i+8] = local_hdr.tv_usec[8*i +: 8];
      for (int i = 0; i < 4; i++)
        pcap_hdr[i+4] = local_hdr.caplen[8*i +: 8];
      for (int i = 0; i < 4; i++)
        pcap_hdr[i] = local_hdr.len[8*i +: 8];
      foreach(pcap_hdr[i]) $fwrite(fd,"%c",pcap_hdr[i]);

      // Writing a packet data
      for (int i = 0; i < pkt_pos; i++) begin
        data = packet[i];
        $fwrite(fd, "%c", data);
      end

      // Clear packet buffer and pkt_pos
      pkt_pos = 0;
      for (int i = 0; i < PKT_MTU_BYTE; i++)
        packet[i] = 8'h0;
	end
    flit_cnt++;
  end

  $fclose(fd);

endtask

bit [TDATA_WIDTH-1:0]   tdata [];
bit [TDATA_WIDTH/8-1:0] tkeep [];
bit                     tlast [];

//bit [511:0] tdata_out [];
//bit [63:0]  tkeep_out [];
//bit         tlast_out [];

initial begin
  read_pcap("f.pcap", DEBUG_ENABLE, tdata, tkeep, tlast);

  write_pcap("output.pcap", DEBUG_ENABLE, tdata, tkeep, tlast);

  for (int i = 0; i < 100000; i++)
    if (tkeep[i] > 0)
      $display("[%d] TDATA:0x%x TKEEP:0x%x TLAST:0x%x", i, tdata[i], tkeep[i], tlast[i]);
  $finish;
end 

endmodule
