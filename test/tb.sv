`timescale 1ps/1ps
module tb();

  localparam CLK_PERIOD = 2500ps;

  localparam FIFO_DEPTH = 16;
  localparam TDATA_WIDTH = 512;


  logic [511:0] m_axis_tdata;
  logic [63:0]  m_axis_tkeep;
  logic         m_axis_tlast;
  logic         m_axis_tvalid;
  logic         m_axis_tready;

  logic [511:0] s_axis_tdata;
  logic [63:0]  s_axis_tkeep;
  logic         s_axis_tlast;
  logic         s_axis_tvalid;
  logic         s_axis_tready;

  /* clocking */
  bit core_clk = 0;
  initial forever #(CLK_PERIOD/2) core_clk = ~core_clk;
  
  /* reset */
  bit core_rst;
  initial begin
    core_rst = 1'b1;
    #(CLK_PERIOD*30);
    core_rst = 1'b0;
  end


  logic fifo_full, fifo_empty, fifo_nearly_full;
  logic fifo_wr_en;

  assign fifo_wr_en = m_axis_tvalid && m_axis_tready;
  assign s_axis_tvalid = !fifo_empty;
  assign m_axis_tready = ~fifo_nearly_full;

  pcap_parser inst_pcap_parser();

  xpm_fifo_sync # (
       .FIFO_WRITE_DEPTH (FIFO_DEPTH),
       .WRITE_DATA_WIDTH (TDATA_WIDTH+TDATA_WIDTH/8+1),
       .PROG_FULL_THRESH (FIFO_DEPTH - 5),
       .READ_MODE        ("FWFT"),
       .FIFO_READ_LATENCY(1),
       .READ_DATA_WIDTH  (TDATA_WIDTH+TDATA_WIDTH/8+1)
  ) fifo_inst (
       .sleep            (1'b0),
       .rst              (core_rst),
       .wr_clk           (core_clk),
       .wr_en            (fifo_wr_en),
       .din              ({m_axis_tdata, m_axis_tkeep, m_axis_tlast}),
       .full             (fifo_full),
       .prog_full        (fifo_nearly_full),
       .wr_data_count    (),
       .overflow         (),
       .wr_rst_busy      (),
       .rd_en            (!fifo_empty && s_axis_tready),
       .dout             ({s_axis_tdata, s_axis_tkeep, s_axis_tlast}),
       .empty            (fifo_empty),
       .prog_empty       (),
       .rd_data_count    (),
       .underflow        (),
       .rd_rst_busy      (),
       .injectsbiterr    (1'b0),
       .injectdbiterr    (1'b0),
       .sbiterr          (),
       .dbiterr          ()
  );

  pkt_replay #(
    .PCAP_FILE_NAME ("in.pcap")
  ) inst_pkt_replay (
    .clk            (core_clk),
    .rst            (core_rst),
  
    .m_axis_tdata   (m_axis_tdata ),
    .m_axis_tkeep   (m_axis_tkeep ),
    .m_axis_tlast   (m_axis_tlast ),
    .m_axis_tvalid  (m_axis_tvalid),
    .m_axis_tready  (m_axis_tready)
  );

  pkt_writer #(
  	.PCAP_FILE_NAME ("output.pcap"),
	.TIMEOUT        (400)
  ) inst_pkt_writer (
    .clk            (core_clk),
    .rst            (core_rst),
  
    .s_axis_tdata   (s_axis_tdata ),
    .s_axis_tkeep   (s_axis_tkeep ),
    .s_axis_tlast   (s_axis_tlast ),
    .s_axis_tvalid  (s_axis_tvalid),
    .s_axis_tready  (s_axis_tready)
  );

  always_comb begin
    //if (s_axis_tvalid && s_axis_tready) begin
    //  $display("[S] TDATA:0x%x TKEEP:0x%x TLAST:0x%x", s_axis_tdata, s_axis_tkeep, s_axis_tlast);
	//end
    //if (m_axis_tvalid && m_axis_tready) begin
    //  $display("[M] TDATA:0x%x TKEEP:0x%x TLAST:0x%x", m_axis_tdata, m_axis_tkeep, m_axis_tlast);
	//end
  end

  initial begin
    $display(" -- simulation begins -- ");
	#100us
    $display(" -- simulation finished -- ");
    $finish;
  end


endmodule
