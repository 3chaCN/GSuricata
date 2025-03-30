#############################
#
# Suricata GTK log viewer 
#
#############################
###
# TODO : - cmdline options (chemins vers les différents logs) 
#        - Remote log fetch
#        - ban ip
#        - event log : gérer les autres entrées que DNS
#        - tri par priorité 
#        - paramètres réseau de l'hôte

import json
import gi
import re
import sys

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk

eve = []
fast = []
http = []

with open("/var/log/suricata/eve.json") as f:
    for line in f:
        if "flow_id" in line:
            eve.append(json.loads(line))

with open("/var/log/suricata/fast.log") as f:
    for line in f:
        fast.append(line)

with open("/var/log/suricata/http.log") as f:
    for line in f:
        http.append(line)

class FastLog(Gtk.Window):
    def __init__(self):
        super().__init__(title="Suricata Logs")
        
        self.set_default_size(800, 600)

        # Conteneur principal
        self.vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.add(self.vbox)

        # Création d'une fenêtre défilante
        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.ALWAYS)
        scrolled_window.set_vexpand(True)  # Permet à la fenêtre défilante d'occuper tout l'espace vertical
        self.vbox.pack_start(scrolled_window, True, True, 0)
        
        self.listbox = Gtk.ListBox()
        scrolled_window.add(self.listbox)
        self.show_fast_log()
        
        button_eve = Gtk.Button(label="All Events")
        button_exit = Gtk.Button(label="Exit")

        self.vbox.pack_start(button_eve, False, False, 0)
        self.vbox.pack_start(button_exit, False, False, 0)

        button_eve.connect("clicked", self.on_button_clicked_eve)
        button_exit.connect("clicked", self.on_button_clicked_exit)
        self.listbox.connect("button-press-event", self.on_button_press_event)
        self.actual_selection = None
        self.menu = Gtk.Menu()

        # Option pour bloquer l'IP
        option1 = Gtk.MenuItem(label="Blacklister")
        option1.connect("activate", self.on_option1_activate)
        self.listbox.connect("row-selected", self.on_row_selected)

        self.menu.append(option1)
        self.menu.show_all()

    def show_fast_log(self):
        self.clear_listbox()

        for lines in fast:
            self.row = Gtk.ListBoxRow()
            label = Gtk.Label()

            # les alertes grave apparaissent en gras (Priorité 1)
            if len(re.findall(r'Priority: 1', lines)) > 0:
                label.set_markup("<b><span background=\"red\" foreground=\"white\" font_size=\"large\">"+lines+"</span></b>")
            else:
                label.set_markup("<span size=\"large\">"+lines+"</span>")
            label.set_xalign(0)

            self.row.add(label)
            self.listbox.add(self.row)
        
        self.listbox.show_all()

    def on_button_clicked_exit(self, button_exit):
        sys.exit(0)

    def on_button_clicked_eve(self, button_eve):
        details = EventDetail()

    def on_button_press_event(self, widget, event):
        # Vérifier si le clic droit a été effectué (bouton 3)
        if event.button == Gdk.BUTTON_SECONDARY:
            # Afficher le menu contextuel à la position du clic
            self.menu.popup(None, None, None, None, event.button, event.time)
            return True

    # blacklist à implémenter
    def on_row_selected(self, listbox, row):
        label = row.get_child()
        if isinstance(label, Gtk.Label):
            text = label.get_text()
            self.actual_selection = text

    def on_option1_activate(self, menu_item):
        print(self.actual_selection)

    def clear_listbox(self):
        # Parcourir et supprimer chaque enfant (GTK 3)
        for child in self.listbox.get_children():
            self.listbox.remove(child)


class EventDetail(Gtk.Window):
    def __init__(self):
        super().__init__(title="Network Events Details")

        self.set_default_size(1000, 800)

        self.grid = Gtk.Grid()
        self.grid.set_column_homogeneous(True)
        self.grid.set_row_homogeneous(True)
        self.add(self.grid)

        # création de la vue en détail et ajout des colonnes
        model = Gtk.ListStore(str, str, str, str, int, str, int, str, str, str)
        for j in range(0, len(eve)):
            if 'dns' or 'flow_id'  in eve[j].keys():
                try:
                    eve[j]['dns'] = str(eve[j]['dns'])
                    del eve[j]['flow_id']
                    model.append(eve[j].values())
                except:
                    pass

        self.treeview = Gtk.TreeView(model=model)        
        for i, column_title in enumerate(
        ['timestamp', 'in_iface', 'event_type', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'pkt_src', 'dns']):
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(column_title, renderer, text=i)
            self.treeview.append_column(column)
        
        self.scrollable_treelist = Gtk.ScrolledWindow()
        self.scrollable_treelist.set_vexpand(True)

        self.grid.attach(self.scrollable_treelist, 0, 0, 8, 10)  
        self.scrollable_treelist.add(self.treeview)
        
        self.show_all()
               
        
 

win = FastLog()
win.connect("destroy", Gtk.main_quit)
win.show_all()
Gtk.main()

