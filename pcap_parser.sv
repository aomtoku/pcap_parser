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
  output bit                     tlast [],
  output int                     size
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
      size = tdata.size();
      $fclose(fd);
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

    $display(" S DEBUG ==== tdata.size() = %u", tdata.size());
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

  $display("DEBUG: AOM FINI");

  $fclose(fd);

  $display("DEBUG: AOM FINI 2");

endtask

bit [TDATA_WIDTH-1:0]   tdata [];
bit [TDATA_WIDTH/8-1:0] tkeep [];
bit                     tlast [];

//bit [511:0] tdata_out [];
//bit [63:0]  tkeep_out [];
//bit         tlast_out [];

initial begin
  //read_pcap("f.pcap", DEBUG_DISABLE, tdata, tkeep, tlast);

  //write_pcap("output.pcap", DEBUG_DISABLE, tdata, tkeep, tlast);

  //for (int i = 0; i < 100000; i++)
  //  if (tkeep[i] > 0)
  //    $display("[%d] TDATA:0x%x TKEEP:0x%x TLAST:0x%x", i, tdata[i], tkeep[i], tlast[i]);
  //$finish;
end 

endmodule

module pkt_replay #(
	parameter PCAP_FILE_NAME = "",
	parameter TDATA_WIDTH    = 512,
	parameter PKT_MTU_SIZE   = 8192
)(
  input  logic                     clk,
  input  logic                     rst,

  output logic   [TDATA_WIDTH-1:0] m_axis_tdata,
  output logic [TDATA_WIDTH/8-1:0] m_axis_tkeep,
  output logic                     m_axis_tlast,
  output logic                     m_axis_tvalid,
  input  logic                     m_axis_tready
);

  bit   [TDATA_WIDTH-1:0] tdata [];
  bit [TDATA_WIDTH/8-1:0] tkeep [];
  bit                     tlast [];
  
  bit [31:0] iter, iter_next;
  bit [31:0] cnt, cnt_next;
  localparam IDLE  = 2'b00;
  localparam START = 2'b01;
  localparam FIN   = 2'b10;
  int size;

  logic [1:0] state_next, state;

  pcap_parser inst_pcap_parser();

  initial begin
    inst_pcap_parser.read_pcap(PCAP_FILE_NAME, 1'b0, tdata, tkeep, tlast, size);
  end
    
  always_comb begin
    state_next = state;
	iter_next = iter;
	cnt_next = cnt;
	m_axis_tvalid = 1'b0;
	m_axis_tdata = 'h0;
	m_axis_tkeep = 'h0;
	m_axis_tlast = 'h0;

    case (state)
    IDLE: begin
	  cnt_next = cnt + 1;
      if (cnt == 30) begin
        state_next = START;
      end
	end
    START: begin
      if (m_axis_tready) begin
	    iter_next = iter + 1;
        m_axis_tvalid = 1'b1;
        m_axis_tdata = tdata[iter];
        m_axis_tkeep = tkeep[iter];
        m_axis_tlast = tlast[iter];
      end
	  if (iter == size) begin
	    state_next = FIN;
	  end
    end
    FIN: begin
      m_axis_tvalid = 1'b0;
      m_axis_tdata = 'h0;
      m_axis_tkeep = 'h0;
      m_axis_tlast = 1'b0;
    end
    endcase
  end

  always_ff @(posedge clk) begin
    if (rst) begin
      iter <= 'h0;
      cnt <= 'h0;
      state <= IDLE;
	end
	else begin
      iter <= iter_next;
      cnt <= cnt_next;
      state <= state_next;
	end
  end

endmodule


module pkt_replay_avalon_st #(
	parameter PCAP_FILE_NAME = "",
	parameter DATA_WIDTH    = 512,
	parameter PKT_MTU_SIZE   = 8192
)(
  input  logic                     clk,
  input  logic                     rst,

  output logic    [DATA_WIDTH-1:0] av_data,
  output logic  [DATA_WIDTH/8-1:0] av_empty,
  output logic                     av_valid,
  output logic                     av_startofpacket,
  output logic                     av_endofpacket,
  output logic                     av_channel,
  output logic                     av_error,
  input  logic                     av_ready
);

  bit   [DATA_WIDTH-1:0] tdata [];
  bit [DATA_WIDTH/8-1:0] tkeep [];
  bit                    tlast [];
  
  bit [31:0] iter, iter_next;
  bit [31:0] cnt, cnt_next;
  localparam IDLE  = 2'b00;
  localparam START = 2'b01;
  localparam FIN   = 2'b10;
  int size;

  logic [1:0] state_next, state;
  logic first_next, first;

  pcap_parser inst_pcap_parser();

  initial begin
    inst_pcap_parser.read_pcap(PCAP_FILE_NAME, 1'b0, tdata, tkeep, tlast, size);
  end
    
  always_comb begin
    state_next = state;
	iter_next = iter;
	cnt_next = cnt;
	first_next = first;
    av_data = 'h0;
	av_empty = 'h0;
	av_startofpacket = 1'b0;
	av_endofpacket = 1'b0;
	av_endofpacket = 1'b0;
	av_valid = 1'b0;
	av_channel = 'h0;
	av_error = 'h0;

    case (state)
    IDLE: begin
	  cnt_next = cnt + 1;
      if (cnt == 30) begin
        state_next = START;
      end
	end
    START: begin
      if (av_ready) begin
        iter_next = iter + 1;
        av_data = tdata[iter];
		if (first) begin
			av_startofpacket = 1'b1;
            first_next = 1'b1;
        end
        av_valid = 1'b1;
      end
      av_endofpacket = tlast[iter];
      if (iter == size) begin
        state_next = FIN;
		av_empty = DATA_WIDTH/8;
        foreach(tkeep[iter])
          av_empty -= tkeep[iter];
	  end
    end
    FIN: begin
      av_data = 'h0;
      av_valid = 1'b0;
      av_empty = 'h0;
      av_startofpacket = 1'b0;
      av_endofpacket = 1'b0;
      av_channel = 1'b0;
      av_error = 1'b0;
      first_next = 1'b0;
    end
    endcase
  end

  always_ff @(posedge clk) begin
    if (rst) begin
      iter <= 'h0;
      cnt <= 'h0;
      state <= IDLE;
	  first <= 1'b0;
	end
	else begin
      iter <= iter_next;
      cnt <= cnt_next;
      state <= state_next;
	  first <= first_next;
	end
  end
endmodule

module pkt_writer #(
    parameter PCAP_FILE_NAME = "",
    parameter TDATA_WIDTH    = 512,
    parameter PKT_MTU_SIZE   = 8192,
    parameter TIMEOUT        = 300
)(
  input  logic                     clk,
  input  logic                     rst,

  input  logic   [TDATA_WIDTH-1:0] s_axis_tdata,
  input  logic [TDATA_WIDTH/8-1:0] s_axis_tkeep,
  input  logic                     s_axis_tlast,
  input  logic                     s_axis_tvalid,
  output logic                     s_axis_tready
);

  bit   [TDATA_WIDTH-1:0] tdata [];
  bit [TDATA_WIDTH/8-1:0] tkeep [];
  bit                     tlast [];

  bit [31:0] counter, wait_counter;

  assign s_axis_tready = 1'b1;

  pcap_parser inst_pcap_parser();

  always_comb begin
    if (s_axis_tvalid && s_axis_tready) begin
      tdata = new[tdata.size() + 1](tdata);
      tkeep = new[tkeep.size() + 1](tkeep);
      tlast = new[tlast.size() + 1](tlast);

      tdata[counter] = s_axis_tdata;
      tkeep[counter] = s_axis_tkeep;
      tlast[counter] = s_axis_tlast;
    end
  end

  always_ff @(posedge clk)
    if (rst) begin
	  counter <= 'h0;
	  wait_counter <= 'h0;
    end
    else begin
      if (s_axis_tvalid && s_axis_tready)
        counter <= counter + 'h1;
      if (!s_axis_tvalid)
        wait_counter <= wait_counter + 'h1;
      else
        wait_counter <= 'h0;
    end

  //always_ff @(posedge clk)
  //  if (s_axis_tvalid && s_axis_tready)
  //    $display("[S_AXIS] TDATA:0x%x TKEEP:0x%x TLAST:0x%x",  s_axis_tdata, s_axis_tkeep, s_axis_tlast);

  initial begin
    wait(wait_counter > TIMEOUT);
    //if (debug)
    //  for (int i = 0; i < tdata.size(); i++)
    //    $display("[WR PCAP] [%4d] TDATA:0x%x TKEEP:0x%x TLAST:0x%x", i, tdata[i], tkeep[i], tlast[i]);
    inst_pcap_parser.write_pcap(PCAP_FILE_NAME, 1'b0, tdata, tkeep, tlast);
    $display("wrote axi-stream flits %d", tdata.size());
	$display("SUMMARY: writting to %s", PCAP_FILE_NAME);
	$finish;
  end

endmodule

module pkt_writer_avalon_st #(
    parameter PCAP_FILE_NAME = "",
    parameter DATA_WIDTH    = 512,
    parameter PKT_MTU_SIZE   = 8192,
    parameter TIMEOUT        = 300
)(
  input  logic                     clk,
  input  logic                     rst,

  input  logic    [DATA_WIDTH-1:0] av_data,
  input  logic  [DATA_WIDTH/8-1:0] av_empty,
  input  logic                     av_valid,
  input  logic                     av_startofpacket,
  input  logic                     av_endofpacket,
  input  logic                     av_channel,
  input  logic                     av_error,
  output logic                     av_ready
);

  bit    [DATA_WIDTH-1:0] tdata [];
  bit  [DATA_WIDTH/8-1:0] tkeep [];
  bit                     tlast [];

  bit [DATA_WIDTH/8*2-1:0] tmp;

  bit [31:0] counter, wait_counter;

  assign s_axis_tready = 1'b1;

  pcap_parser inst_pcap_parser();

  always_comb begin
    if (av_valid && av_ready) begin
      tdata = new[tdata.size() + 1](tdata);
      tkeep = new[tkeep.size() + 1](tkeep);
      tlast = new[tlast.size() + 1](tlast);

      tdata[counter] = av_data;
      tlast[counter] = av_endofpacket;
      if (av_empty == 'h0) 
        tkeep[counter] = {(DATA_WIDTH/8){1'b1}};
      else begin
        tmp = {(DATA_WIDTH/8*2){1'b1}} >> av_empty;
        tkeep[counter] = tmp[DATA_WIDTH/8*2-1:DATA_WIDTH/8];
      end
    end
  end

  always_ff @(posedge clk)
    if (rst) begin
	  counter <= 'h0;
	  wait_counter <= 'h0;
    end
    else begin
      if (av_valid && av_ready)
        counter <= counter + 'h1;
      if (!av_valid)
        wait_counter <= wait_counter + 'h1;
      else
        wait_counter <= 'h0;
    end

  //always_ff @(posedge clk)
  //  if (s_axis_tvalid && s_axis_tready)
  //    $display("[S_AXIS] TDATA:0x%x TKEEP:0x%x TLAST:0x%x",  s_axis_tdata, s_axis_tkeep, s_axis_tlast);

  initial begin
    wait(wait_counter > TIMEOUT);
    //if (debug)
    //  for (int i = 0; i < tdata.size(); i++)
    //    $display("[WR PCAP] [%4d] TDATA:0x%x TKEEP:0x%x TLAST:0x%x", i, tdata[i], tkeep[i], tlast[i]);
    inst_pcap_parser.write_pcap(PCAP_FILE_NAME, 1'b0, tdata, tkeep, tlast);
    $display("wrote axi-stream flits %d", tdata.size());
	$display("SUMMARY: writting to %s", PCAP_FILE_NAME);
	$finish;
  end

endmodule
