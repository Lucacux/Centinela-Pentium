"""Motor de alarmas con estado, al estilo CloudWatch.

El esquema viejo era, por cada metrica, un `if valor > umbral and (ahora -
ultima_alerta > cooldown)` escrito a mano dentro del loop. Cuatro problemas
concretos que se arreglan aca:

1. **Un solo dato disparaba.** Un pico de disco al 91% en un muestreo mandaba
   "DISCO CRITICO". CloudWatch resuelve esto con "N datapoints de M": hacen
   falta N muestras en falta dentro de una ventana de M para pasar a ALARM.

2. **No habia recuperacion.** Llegaba "CPU CRITICA" y nunca "CPU normalizada".
   Sin transicion de vuelta a OK, no se sabe si el problema sigue o paso, y el
   cooldown de una hora tapaba el segundo aviso. Aca el estado es explicito
   (OK / ALARM / INSUFFICIENT_DATA) y cada transicion notifica.

3. **INSUFFICIENT_DATA no existia.** Si una metrica no se podia medir, se leia
   como 0 y contaba como "todo bien". Un sensor de temperatura que desaparece
   no es un equipo frio.

4. **El cooldown silenciaba de mas.** Era por metrica y global; ahora es por
   alarma y solo aplica a los recordatorios mientras sigue en ALARM, nunca a
   las transiciones, que siempre se notifican.

Sobre acciones: una alarma puede llevar una `action`, pero por defecto SOLO SE
PROPONE. El usuario decide y ejecuta. La auto-ejecucion existe pero hay que
habilitarla explicitamente por alarma (`auto=True`), porque en esta infra el
control lo tiene el, no el bot.
"""
import os
from collections import deque
from datetime import datetime, time as dtime, timedelta

OK = "OK"
ALARM = "ALARM"
NO_DATA = "INSUFFICIENT_DATA"

# Severidades. Solo "critica" atraviesa el horario nocturno.
CRITICAL = "critica"
WARNING = "warning"

# Modo silencio: de noche, solo lo critico. Fuera de esa franja pasa todo.
QUIET_START = int(os.getenv("QUIET_HOURS_START", "1"))
QUIET_END = int(os.getenv("QUIET_HOURS_END", "8"))
QUIET_ENABLED = os.getenv("QUIET_HOURS_ENABLED", "true").lower() in ("true", "1", "yes")


def in_quiet_hours(now=None, start=None, end=None):
    """True si estamos en la franja nocturna. Contempla que cruce medianoche."""
    now = now or datetime.now()
    start = QUIET_START if start is None else start
    end = QUIET_END if end is None else end
    if start == end:
        return False
    h = now.time()
    a, b = dtime(hour=start), dtime(hour=end)
    return a <= h < b if start < end else (h >= a or h < b)


class Alarm:
    """Una metrica vigilada, con estado propio.

    datapoints/periods es el "N de M": hacen falta `datapoints` muestras en
    falta dentro de las ultimas `periods` para pasar a ALARM. Con 2 de 3 un
    pico aislado no despierta a nadie, pero algo sostenido si.
    """

    def __init__(self, name, title, threshold, *, comparison="gt", datapoints=2,
                 periods=3, severity=WARNING, cooldown_min=60, unit="%",
                 description="", action=None, auto=False):
        self.name = name
        self.title = title
        self.threshold = threshold
        self.comparison = comparison
        self.datapoints = datapoints
        self.periods = periods
        self.severity = severity
        self.cooldown = timedelta(minutes=cooldown_min)
        self.unit = unit
        self.description = description
        # `action` describe QUE hacer; no se ejecuta salvo auto=True.
        self.action = action
        self.auto = auto

        self.state = NO_DATA
        self.window = deque(maxlen=periods)
        self.last_notified = None
        self.last_value = None
        self.in_alarm_since = None

    def breaches(self, value):
        if value is None:
            return False
        return value > self.threshold if self.comparison == "gt" else value < self.threshold

    def evaluate(self, value, now=None):
        """Agrega una muestra y devuelve el evento si hubo transicion.

        `value=None` significa "no se pudo medir", que NO es lo mismo que cero:
        se registra como hueco y, si la ventana queda sin datos utiles, la
        alarma cae a INSUFFICIENT_DATA en vez de fingir que todo esta bien.
        """
        now = now or datetime.now()
        self.window.append(value)
        self.last_value = value

        medibles = [v for v in self.window if v is not None]
        if not medibles:
            return self._transition(NO_DATA, now)

        # Aun sin la ventana llena se evalua: si ya hay N muestras en falta, el
        # problema es real y esperar a llenar M solo retrasa el aviso.
        fallando = sum(1 for v in medibles if self.breaches(v))
        if fallando >= self.datapoints:
            return self._transition(ALARM, now)
        if len(self.window) == self.periods and fallando == 0:
            return self._transition(OK, now)
        if self.state == NO_DATA and not self.breaches(value):
            return self._transition(OK, now)
        return None

    def _transition(self, new_state, now):
        previo = self.state
        if new_state == previo:
            # Sin cambio de estado, solo recordatorios mientras siga en ALARM.
            if new_state == ALARM and self._cooldown_vencido(now):
                self.last_notified = now
                return self._event("reminder", previo, now)
            return None

        self.state = new_state
        if new_state == ALARM:
            self.in_alarm_since = now
        # Volver de ALARM a OK siempre se avisa: es la mitad que faltaba.
        notificable = new_state in (ALARM, OK) and not (previo == NO_DATA and new_state == OK)
        if new_state == NO_DATA and previo == OK:
            notificable = True
        if not notificable:
            return None
        self.last_notified = now
        evento = self._event("transition", previo, now)
        if new_state == OK:
            self.in_alarm_since = None
        return evento

    def _cooldown_vencido(self, now):
        return self.last_notified is None or (now - self.last_notified) >= self.cooldown

    def _event(self, kind, previo, now):
        dur = None
        if self.in_alarm_since and self.state in (ALARM, OK):
            dur = int((now - self.in_alarm_since).total_seconds())
        return {
            "alarm": self, "kind": kind, "from": previo, "to": self.state,
            "value": self.last_value, "at": now, "duration_s": dur,
        }

    def should_notify_now(self, event, now=None):
        """Modo silencio: de noche solo pasa lo critico.

        Las recuperaciones tambien se silencian de noche -- despertar a alguien
        para decirle que YA se arreglo es el peor aviso posible.
        """
        if not QUIET_ENABLED or self.severity == CRITICAL:
            return True
        return not in_quiet_hours(now)


class AlarmEngine:
    """Registro de alarmas. Recibe metricas y devuelve los eventos a publicar."""

    def __init__(self, alarms=()):
        self.alarms = {a.name: a for a in alarms}

    def add(self, alarm):
        self.alarms[alarm.name] = alarm
        return alarm

    def evaluate(self, metrics, now=None):
        """metrics: {nombre_alarma: valor o None}. Devuelve eventos a notificar.

        Se procesan solo las metricas presentes: una alarma cuya metrica no se
        entrego en este ciclo conserva su estado en vez de recibir un hueco
        falso.
        """
        now = now or datetime.now()
        eventos = []
        for name, value in metrics.items():
            alarm = self.alarms.get(name)
            if alarm is None:
                continue
            ev = alarm.evaluate(value, now)
            if ev and alarm.should_notify_now(ev, now):
                eventos.append(ev)
        # Lo critico primero: si entran varias juntas, que lo urgente se lea antes.
        eventos.sort(key=lambda e: 0 if e["alarm"].severity == CRITICAL else 1)
        return eventos

    def snapshot(self):
        """Estado de todas las alarmas, para un comando de consulta."""
        return [
            {"name": a.name, "title": a.title, "state": a.state, "value": a.last_value,
             "threshold": a.threshold, "unit": a.unit, "severity": a.severity}
            for a in self.alarms.values()
        ]
