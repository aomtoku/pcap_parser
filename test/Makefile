all: questa

.PHONY: questa
questa:
	vsim -64 -c -do "questa.sim"

.PHONY: gui-questa
gui-questa:
	vsim -64 -do "questa.sim" -gui

.PHONY: clean
clean:
	rm -rf msim 
	rm -f transcript vivado* *.wlf
	rm -rf xil_defaultlib
