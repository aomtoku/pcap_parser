module tc #(
  parameter INTVAL_F    = 0,
  parameter INTVAL_S    = 0,
  parameter TDATA_WIDTH = 512,
  parameter TUSER_WIDTH = 1,
) (
  input                            clk,
  input                            rst,

  input  logic   [TDATA_WIDTH-1:0] s_axis_tdata,
  input  logic [TDATA_WIDTH/8-1:0] s_axis_tkeep,
  input  logic   [TUSER_WIDTH-1:0] s_axis_tuser,
  input  logic                     s_axis_tlast,
  input  logic                     s_axis_tvalid,
  output logic                     s_axis_tready,

  output logic   [TDATA_WIDTH-1:0] m_axis_tdata,
  output logic [TDATA_WIDTH/8-1:0] m_axis_tkeep,
  output logic   [TUSER_WIDTH-1:0] m_axis_tuser,
  output logic                     m_axis_tlast,
  output logic                     m_axis_tvalid,
  input  logic                     m_axis_tready
);

  logic fifo_full, fifo_empty, fifo_nearly_full;
  logic fifo_wr_en;

  assign fifo_wr_en = m_axis_tvalid && m_axis_tready;
  assign s_axis_tvalid = !fifo_empty;
  assign m_axis_tready = ~fifo_nearly_full;

  xpm_fifo_sync # (
       .FIFO_WRITE_DEPTH (FIFO_DEPTH),
       .WRITE_DATA_WIDTH (TDATA_WIDTH+TDATA_WIDTH/8+1),
       .PROG_FULL_THRESH (FIFO_DEPTH - 5),
       .READ_MODE        ("FWFT"),
       .FIFO_READ_LATENCY(1),
       .READ_DATA_WIDTH  (TDATA_WIDTH+TDATA_WIDTH/8+1)
  ) fifo_inst (
       .sleep            (1'b0),
       .rst              (rst),
       .wr_clk           (clk),
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

  logic [31:0] icnt, pcnt, icnt_next, pcnt_next;
  logic icnt_val, icnt_val_next, pcnt_val, pcnt_val_next;

  always_comb begin
    icnt_next = icnt;
    pcnt_next = pcnt;

    if (!fifo_empty && s_axis_tready && ~s_axis_tlast && icnt_val == 1'b0) begin
      icnt_val_next = 1'b1;
      fifo_rd_en = 1'b1;
    end

    if (!fifo_empty && s_axis_tready && ~s_axis_tlast && icnt_val && icnt == INTVAL_F - 1) begin
      icnt_val_next = 1'b1;
      fifo_rd_en = 1'b1;
      icnt_next = 0;
    end

    if (icnt_val) begin
      icnt_next = icnt_next + 1;
    end

    if (!fifo_empty && s_axis_tready && s_axis_tlast && pcnt_val == 1'b0) begin
      pcnt_val_next = 1'b1;
    end 
    if (!fifo_empty && s_axis_tready && pcnt_val && pcnt == INTVAL_S - 1) begin
      pcnt_val_next = 1'b0;
      pcnt_next = 0;
    end

    if (pcnt_val) begin
      pcnt_next = pcnt_next + 1;
    end
  end



  always_ff @(posedge clk) begin
    if (rst) begin
      icnt <= 'h0;
      pcnt <= 'h0;
    end
    else begin
      icnt <= icnt_next;
      pcnt <= pcnt_next;
    end
  end

endmodule
