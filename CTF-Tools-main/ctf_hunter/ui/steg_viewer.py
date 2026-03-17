"""
Steg Viewer tab: bit plane viewer, LSB plane image, channel isolator, histogram.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QScrollArea, QSizePolicy, QSpinBox, QPushButton,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QImage, QColor


class StegViewerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._image_path: str = ""
        self._img = None  # PIL Image

        layout = QVBoxLayout(self)

        # Controls row
        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Channel:"))
        self._channel_combo = QComboBox()
        self._channel_combo.addItems(["R", "G", "B", "A", "Luminance"])
        ctrl.addWidget(self._channel_combo)

        ctrl.addWidget(QLabel("Bit Plane:"))
        self._bit_spin = QSpinBox()
        self._bit_spin.setRange(0, 7)
        ctrl.addWidget(self._bit_spin)

        self._show_lsb_btn = QPushButton("Show LSB Plane")
        self._show_lsb_btn.clicked.connect(self._show_lsb)
        ctrl.addWidget(self._show_lsb_btn)

        self._show_channel_btn = QPushButton("Isolate Channel")
        self._show_channel_btn.clicked.connect(self._show_channel)
        ctrl.addWidget(self._show_channel_btn)

        self._show_histogram_btn = QPushButton("Histogram")
        self._show_histogram_btn.clicked.connect(self._show_histogram)
        ctrl.addWidget(self._show_histogram_btn)

        self._show_bit_plane_btn = QPushButton("Show Bit Plane")
        self._show_bit_plane_btn.clicked.connect(self._show_bit_plane)
        ctrl.addWidget(self._show_bit_plane_btn)

        ctrl.addStretch()
        layout.addLayout(ctrl)

        # Image display
        self._scroll = QScrollArea()
        self._img_label = QLabel("Load an image file and select it to view steg analysis.")
        self._img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._scroll.setWidget(self._img_label)
        self._scroll.setWidgetResizable(True)
        layout.addWidget(self._scroll)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

    def load_image(self, path: str) -> None:
        self._image_path = path
        try:
            from PIL import Image
            self._img = Image.open(path)
            self._status_label.setText(
                f"Loaded: {path}  |  Mode: {self._img.mode}  |  Size: {self._img.size}"
            )
            # Show original image
            self._display_pil_image(self._img)
        except Exception as exc:
            self._status_label.setText(f"Error loading image: {exc}")

    def _display_pil_image(self, img) -> None:
        try:
            from PIL import Image
            import numpy as np
            # Scale to fit if too large
            max_w, max_h = 900, 600
            w, h = img.size
            scale = min(max_w / max(w, 1), max_h / max(h, 1), 1.0)
            if scale < 1.0:
                new_size = (int(w * scale), int(h * scale))
                img = img.resize(new_size, Image.NEAREST)
            # Convert to QImage
            rgb = img.convert("RGBA")
            data = rgb.tobytes("raw", "RGBA")
            qimg = QImage(data, rgb.width, rgb.height, QImage.Format.Format_RGBA8888)
            self._img_label.setPixmap(QPixmap.fromImage(qimg))
        except Exception as exc:
            self._img_label.setText(f"Display error: {exc}")

    def _channel_index(self) -> int:
        ch_name = self._channel_combo.currentText()
        if self._img is None:
            return 0
        mode = self._img.mode
        if ch_name == "Luminance":
            return 0
        mapping = {"R": 0, "G": 1, "B": 2, "A": 3}
        return mapping.get(ch_name, 0)

    def _show_lsb(self) -> None:
        if self._img is None:
            return
        try:
            from PIL import Image
            import numpy as np
            arr = np.array(self._img)
            ch = self._channel_index()
            if arr.ndim == 3 and ch < arr.shape[2]:
                plane = ((arr[:, :, ch] & 1) * 255).astype("uint8")
            elif arr.ndim == 2:
                plane = ((arr & 1) * 255).astype("uint8")
            else:
                return
            result = Image.fromarray(plane, mode="L")
            self._display_pil_image(result)
            self._status_label.setText(f"LSB plane of channel {self._channel_combo.currentText()}")
        except Exception as exc:
            self._status_label.setText(f"LSB error: {exc}")

    def _show_bit_plane(self) -> None:
        if self._img is None:
            return
        try:
            from PIL import Image
            import numpy as np
            bit = self._bit_spin.value()
            arr = np.array(self._img)
            ch = self._channel_index()
            if arr.ndim == 3 and ch < arr.shape[2]:
                plane = (((arr[:, :, ch] >> bit) & 1) * 255).astype("uint8")
            elif arr.ndim == 2:
                plane = (((arr >> bit) & 1) * 255).astype("uint8")
            else:
                return
            result = Image.fromarray(plane, mode="L")
            self._display_pil_image(result)
            self._status_label.setText(
                f"Bit plane {bit} of channel {self._channel_combo.currentText()}"
            )
        except Exception as exc:
            self._status_label.setText(f"Bit plane error: {exc}")

    def _show_channel(self) -> None:
        if self._img is None:
            return
        try:
            from PIL import Image
            import numpy as np
            arr = np.array(self._img)
            ch_name = self._channel_combo.currentText()
            ch = self._channel_index()
            if ch_name == "Luminance":
                gray = self._img.convert("L")
                self._display_pil_image(gray)
                self._status_label.setText("Luminance channel")
                return
            if arr.ndim == 3 and ch < arr.shape[2]:
                isolated = np.zeros_like(arr)
                isolated[:, :, ch] = arr[:, :, ch]
                result_mode = self._img.mode
                result = Image.fromarray(isolated.astype("uint8"), mode=result_mode)
                self._display_pil_image(result)
                self._status_label.setText(f"Isolated channel: {ch_name}")
        except Exception as exc:
            self._status_label.setText(f"Channel isolation error: {exc}")

    def _show_histogram(self) -> None:
        if self._img is None:
            return
        try:
            from PIL import Image
            import numpy as np
            arr = np.array(self._img)
            ch = self._channel_index()
            ch_name = self._channel_combo.currentText()
            if arr.ndim == 3 and ch < arr.shape[2]:
                channel_data = arr[:, :, ch].flatten()
            else:
                channel_data = arr.flatten()

            # Build a simple histogram image (256 wide, 100 tall)
            hist = np.zeros(256, dtype=int)
            for v in channel_data:
                hist[int(v) % 256] += 1
            max_count = max(hist) if max(hist) > 0 else 1
            height = 100
            hist_img = np.zeros((height, 256, 3), dtype="uint8")
            for x, count in enumerate(hist):
                bar_height = int(count / max_count * height)
                hist_img[height - bar_height:, x] = [100, 149, 237]  # cornflower blue

            result = Image.fromarray(hist_img, mode="RGB")
            self._display_pil_image(result)
            self._status_label.setText(
                f"Pixel histogram for channel {ch_name} — max count: {max_count}"
            )
        except Exception as exc:
            self._status_label.setText(f"Histogram error: {exc}")
