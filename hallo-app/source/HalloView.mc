import Toybox.Graphics;
import Toybox.WatchUi;

class HalloView extends WatchUi.View {
    function initialize() {
        View.initialize();
    }

    function onLayout(dc) {}

    function onUpdate(dc) {
        dc.setColor(Graphics.COLOR_WHITE, Graphics.COLOR_BLACK);
        dc.clear();
        dc.drawText(
            dc.getWidth() / 2,
            dc.getHeight() / 2,
            Graphics.FONT_LARGE,
            "Hallo",
            Graphics.TEXT_JUSTIFY_CENTER | Graphics.TEXT_JUSTIFY_VCENTER
        );
    }
}
