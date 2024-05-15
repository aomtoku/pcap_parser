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

  always_comb begin
  end

  always_ff @(posedge clk) begin
    if (rst) begin
    end
    else begin
    end
  end

endmodule
