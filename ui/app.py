import tkinter as tk
from tkinter import ttk
import threading
import time

class NetworkVisualizerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP/ARQ Sliding Window Visualizer")
        self.root.geometry("1000x700")

        # --- Top Control Panel ---
        control_frame = ttk.Frame(root, padding="10")
        control_frame.pack(fill=tk.X)

        self.start_btn = ttk.Button(control_frame, text="Start Simulation", command=self.start_sim)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.pause_btn = ttk.Button(control_frame, text="Pause", command=self.pause_sim, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)

        ttk.Label(control_frame, text="Drop Rate %:").pack(side=tk.LEFT, padx=5)
        self.loss_slider = ttk.Scale(control_frame, from_=0, to=50, orient=tk.HORIZONTAL, length=150)
        self.loss_slider.set(10) # Default 10% loss
        self.loss_slider.pack(side=tk.LEFT, padx=5)

        # --- Main Visual Area (Canvas for Windows and Pipes) ---
        self.canvas = tk.Canvas(root, bg="white", height=300)
        self.canvas.pack(fill=tk.X, padx=10, pady=10)
        
        # Draw placeholder labels
        self.canvas.create_text(200, 20, text="Sender Window (Circular Buffer)", font=("Arial", 12, "bold"))
        self.canvas.create_text(800, 20, text="Receiver Window (Circular Buffer)", font=("Arial", 12, "bold"))
        self.canvas.create_text(500, 150, text="Network Pipe (Packets in Flight) ->", font=("Arial", 12, "italic"))

        # --- Bottom Panel (Graphs) ---
        self.graph_frame = ttk.Frame(root, height=200, relief=tk.SUNKEN)
        self.graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(self.graph_frame, text="Congestion Window (cwnd) over time will appear here.", font=("Arial", 10)).pack(pady=50)

        # Simulation State
        self.running = False
        self.tick = 0

    def start_sim(self):
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.pause_btn.config(state=tk.NORMAL)
        # Run simulation loop in a background thread so UI doesn't freeze
        threading.Thread(target=self.sim_loop, daemon=True).start()

    def pause_sim(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.pause_btn.config(state=tk.DISABLED)

    def sim_loop(self):
        while self.running:
            self.tick += 1
            # Here is where we will hook in the core engine (NetworkChannel, protocols.handle_tick)
            current_loss_rate = self.loss_slider.get() / 100.0
            
            # Print to console for now to prove the loop is running
            print(f"Tick: {self.tick} | Network Loss Rate: {current_loss_rate:.2f}")
            
            # TODO: Update UI Canvas based on protocol buffer states
            
            time.sleep(0.5) # 500ms per tick for visual clarity

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkVisualizerApp(root)
    root.mainloop()