"""Router endpoint: the right column. Power + signal sit *directly above* the
router art; the ESSID sits *directly below* it (the name labels the router),
then BSSID and the channel. Encryption is NOT shown here. It lives in the log
('Target acquired … WPA2'), the under-sparkline footer, and is implied by the
attack buttons; the channel alone keeps this column uncluttered.

The power line is the live reception-quality meter: the rainbow
``render_signal_bar`` (beacons/s out of ~9.8), widened to fill the column's
negative space, with the dBm flush right. No "Beacons:" prefix: the
bar *is* the readout."""
from __future__ import annotations

import math
import time

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Label

from ...signal_bar import render_signal_bar
from .art import BreathingArt, art_size


class RouterEndpoint(Vertical):
    def __init__(self, *, essid: str = "", bssid: str = "", channel: int = 0,
                 power_dbm: int = -100, signal: float | None = None,
                 identity: str = "", identity_tip: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._essid = essid
        self._bssid = bssid
        self._channel = channel
        self._power_dbm = power_dbm
        self._signal = signal
        self._identity = identity
        self._identity_tip = identity_tip
        self._width = art_size("focus-ap.ans")[0]      # endpoint column width
        self._last: dict[str, str] = {}                # last-pushed label value; skip no-op repaints

    def compose(self) -> ComposeResult:
        yield Label(self._power_line(), classes="ap-power", id="ap-power")
        yield BreathingArt("focus-ap.ans", classes="endpoint-art")
        yield Label(self._essid_markup(self._essid), classes="ap-essid", id="ap-essid")
        yield Label(self._bssid, classes="ap-static", id="ap-bssid")
        chan = Label(self._channel_markup(), classes="ap-static", id="ap-chan")
        chan.tooltip = self._identity_tip
        yield chan

    def update(self, *, essid: str, bssid: str, channel: int,
               power_dbm: int, signal: float | None, identity: str = "",
               identity_tip: str | None = None) -> None:
        """Power meter repaints every tick (the live readout); the identity facts only
        change on a target switch, so they go through ``_push`` to skip the no-op repaint
        (a blind ``Label.update`` at 10 Hz burns CPU and wipes text selection)."""
        self._essid, self._bssid, self._channel = essid, bssid, channel
        self._power_dbm, self._signal = power_dbm, signal
        self._identity, self._identity_tip = identity, identity_tip
        self.query_one("#ap-power", Label).update(self._power_line())
        self._push("#ap-essid", self._essid_markup(essid))
        self._push("#ap-bssid", bssid)
        self._push("#ap-chan", self._channel_markup())
        self.query_one("#ap-chan", Label).tooltip = identity_tip

    def _push(self, sel: str, value: str) -> None:
        """Update the label only when its value changed: skip the no-op repaint."""
        if self._last.get(sel) == value:
            return
        self._last[sel] = value
        self.query_one(sel, Label).update(value)

    def flicker(self) -> None:
        """Pulse the router LED. The screen calls this on RX from the target."""
        self.query_one(BreathingArt).pulse()

    def _channel_markup(self) -> str:
        if not self._identity:
            return f"channel {self._channel}"
        return f"ch {self._channel} · {self._identity}"

    @staticmethod
    def _essid_markup(essid: str) -> str:
        """The ESSID as a black-on-cyan chip so it pops as the AP's identity (it
        kept blending in as plain bold white). A cloaked AP stays a dim italic
        marker: no chip on a name we don't have."""
        if essid == "‹hidden›":
            return "[dim italic]‹hidden›[/dim italic]"
        return f"[black bold on cyan] {escape(essid)} [/black bold on cyan]"

    def _power_line(self) -> Text:
        """Rainbow signal bar (left, filling the negative space) + dBm (right).
        ``self._signal`` is the windowed beacons/s: None=warming, ~0=dead (a
        heartbeat-pulsing ╳)."""
        dbm = f"{self._power_dbm} dBm"
        bar_w = max(4, self._width - len(dbm) - 1)
        pulse = 0.5 + 0.5 * math.sin(time.time() * math.tau)   # dead-AP heartbeat
        line = Text(no_wrap=True)
        line.append_text(render_signal_bar(self._signal, width=bar_w, pulse=pulse))
        line.append(" ")
        line.append(dbm)
        return line
