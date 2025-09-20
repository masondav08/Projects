import sys, sqlite3, pandas as pd, matplotlib.pyplot as plt
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

class WifiApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wi-Fi Monitor")
        self.layout = QVBoxLayout()

        self.button = QPushButton("Load Data")
        self.button.clicked.connect(self.load_data)
        self.layout.addWidget(self.button)

        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvas(self.fig)
        self.layout.addWidget(self.canvas)

        self.setLayout(self.layout)

    def load_data(self):
        conn = sqlite3.connect("wifi_obs.db")
        df = pd.read_sql_query("SELECT * FROM wifi_obs ORDER BY timestamp DESC LIMIT 50", conn)
        conn.close()
        self.ax.clear()
        if not df.empty:
            df.groupby("ssid")["signal"].mean().plot(kind="bar", ax=self.ax)
        self.canvas.draw()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WifiApp()
    window.show()
    sys.exit(app.exec())
