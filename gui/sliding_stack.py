"""Custom QStackedWidget with sliding animations."""

from PyQt6.QtWidgets import QStackedWidget
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve, QPoint

class SlidingStackedWidget(QStackedWidget):
    """A QStackedWidget that slides its pages horizontally."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._animating = False
        self._anim = None

    def slide_to_index(self, index: int, direction: str = "auto"):
        """Slide to a specific index. 
        direction can be 'left', 'right', or 'auto' (based on index comparison).
        """
        if self._animating or index == self.currentIndex():
            self.setCurrentIndex(index)
            return

        current_idx = self.currentIndex()
        if direction == "auto":
            direction = "right" if index > current_idx else "left"

        current_widget = self.widget(current_idx)
        next_widget = self.widget(index)

        width = self.width()
        
        # Position next_widget off-screen
        offset_x = width if direction == "right" else -width
        next_widget.setGeometry(0, 0, width, self.height())
        
        next_widget.move(offset_x, 0)
        next_widget.show()
        next_widget.raise_()

        self._animating = True
        self._anim = QPropertyAnimation(next_widget, b"pos")
        self._anim.setDuration(300)
        self._anim.setStartValue(QPoint(offset_x, 0))
        self._anim.setEndValue(QPoint(0, 0))
        self._anim.setEasingCurve(QEasingCurve.Type.OutQuart)

        def on_finished():
            self.setCurrentIndex(index)
            self._animating = False

        self._anim.finished.connect(on_finished)
        self._anim.start()
