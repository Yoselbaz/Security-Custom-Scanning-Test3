from django.db.models.expressions import RawSQL
from django.db.models import Count, Q
import datetime
from collections import defaultdict

from server.catalogs.models import NodeScheduled, Node
from server.catalogs.constants import NODE_STATES
from server.logger import NLog
from server.core.signals import catalog_changed
from server.catalogs.scheduled.queries import SQL_GET_TO_ACTIVATE_NODES, SQL_GET_TO_DEACTIVATE_NODES, \
    SQL_GET_EXPIRED_SCHEDULES
from server.catalogs.scheduled.consts import SCHEDULE_DATE_FORMAT, \
    ERROR_WRONG_RANGE, ERROR_MISSING_DATA, ERROR_NO_NODE_FOUND

logger = NLog("catalog-node-schedule")


def enrich_nodes_with_schedules(nodes_dict):
    """
    Adds the "schedules" property to a dict with nodes data.
    """
    grouped_nodes_schedules = get_node_schedules(list(nodes_dict.keys()))
    for node_id in nodes_dict:
        nodes_dict[node_id]['schedules'] = grouped_nodes_schedules[node_id]


def get_node_schedules(node_ids):
    """
    Get the current schedules for nodes
    :param node_ids: The nodes to get the schedules for.
    :return: dict(node_id:[schedules])
    """
    logger_params = dict(node_ids=node_ids)
    logger.info("Requesting node schedule", params=logger_params)

    nodes_schedules = NodeScheduled.objects.filter(Q(node_id__in=node_ids)) \
        .values('start_date', 'end_date', 'id', 'node_id') \
        .order_by('start_date').all()

    grouped_nodes_schedules = defaultdict(list)

    for schedule in nodes_schedules:
        grouped_nodes_schedules[schedule['node_id']].append(schedule)

    return grouped_nodes_schedules


def validate_and_save_scheduled(node_id, schedule_from, schedule_until, is_forever):
    """
    Add a new schedule for a node and update his state if needed.
    :param node_id: The node to add the schedule for
    :param schedule_from: The schedule start date
    :param schedule_until: The schedule start date (if range)
    :param is_forever: boolean True=coming soon (date-forever) | False=Range (date-date)
    :return: Tuple (bool-was_successful, str-error)
    """
    logger_params = dict(node_id=node_id,
                         schedule_from=schedule_from,
                         schedule_until=schedule_until,
                         is_forever=is_forever)
    logger.info("Requesting to add node schedule", params=logger_params)

    if not node_id or not schedule_from or (not schedule_until and not is_forever):
        logger.error("Mising data while adding node schedule", params=logger_params)
        return False, ERROR_MISSING_DATA

    node = Node.objects.filter(id=node_id).first()
    if not node:
        logger.error("Invalid node", params=logger_params)
        return False, ERROR_NO_NODE_FOUND

    schedule_from = datetime.datetime.strptime(schedule_from, SCHEDULE_DATE_FORMAT)
    schedule_until = datetime.datetime.strptime(schedule_until, SCHEDULE_DATE_FORMAT) \
        if not is_forever else None

    if schedule_until and schedule_until < schedule_from:
        logger.warning("Requested end date is before start date on node schedule", params=logger_params)
        return False, ERROR_WRONG_RANGE

    new_scheduled = NodeScheduled(node_id=node.id,
                                  start_date=schedule_from,
                                  end_date=schedule_until)
    new_scheduled.save()
    logger_params['schedule_id'] = new_scheduled.id
    logger.info("Successfully added new node schedule", params=logger_params)

    _update_single_node(node)
    return True, None


def set_node_schedule_flag(node_id, enabled):
    """
    Set the schedule flag for a node and update his state if needed.
    :param node_id: The node to update
    :param enabled: If the enable or disable the schedule flag.
    :return: Tuple (int-shop_id, str-error)
    """
    logger_params = dict(node_id=node_id,
                         enabled=enabled)
    logger.info("Requesting to update node schedule flag", params=logger_params)

    node = Node.objects.filter(id=node_id).first()

    if not node:
        return None, ERROR_NO_NODE_FOUND

    node.scheduled = enabled
    node.save()
    logger.info("Successfully updated node schedule flag", params=logger_params)

    # Update if needed
    if enabled:
        _update_single_node(node)

    return node.shop_id, None


def remove_schedule(range_id, node_id):
    """
    Remove a schedule for a node and update his state if needed.
    :param range_id: The schedule id to remove
    :param node_id: The node id
    """
    logger_params = dict(node_id=node_id,
                         range_id=range_id)
    logger.info("Requesting to remove node schedule", params=logger_params)

    node_schedule = NodeScheduled.objects.filter(id=range_id).first()
    if node_schedule is None:
        logger.warning("Schedule doesn't exists possibly it already removed, skipping..", params=logger_params)
        return

    node = node_schedule.node
    node_schedule.delete()
    logger.info("Successfully removed node schedule", params=logger_params)

    if not node:
        logger.error("Removed a schedule for a non existing node", params=logger_params)
        return

    _update_single_node(node)


def _get_nodes_to_activate():
    """
    Get the list of nodes that are currently inactive but supposed to be active according to the schedules
    :return: tuple(list of in range nodes, list of nodes to be active forever)
    """
    in_range_nodes = Node.objects.raw(SQL_GET_TO_ACTIVATE_NODES)
    forever_nodes = [node.id for node in in_range_nodes if node.is_forever]
    active_nodes = [node.id for node in in_range_nodes if not node.is_forever]
    logger.info("Got to activate nodes", params=dict(forever_nodes=forever_nodes,
                                                     active_nodes=active_nodes))
    return active_nodes, forever_nodes


def _update_node_shops_cache(nodes_objects):
    """
    Update the cache for the shops of the updated nodes.
    :param nodes_objects: The django objects of the changed nodes.
    """
    # Get a set of shops for not updating the same shop twice.
    shops_to_refresh = {int(node.shop_id) for node in nodes_objects}
    for shop_id in shops_to_refresh:
        catalog_changed(shop_id)


def activate_in_range_nodes(active_nodes, forever_nodes):
    """
    Take all the nodes that have a scheduled that is currently in range, but the nodes are inactive.
    Switch them to active.
    :param active_nodes: The list of node ids that are currently in the active dates.
    :param forever_nodes: The list of node ids that needs to be active forever from now.
    :return:
    """
    logger_params = dict(active_nodes=active_nodes,
                         forever_nodes=forever_nodes)
    # TODO : Specifically filter nodes in initial query
    logger.info("Activating in range nodes", params=logger_params)
    to_active_nodes = Node.objects.filter(id__in=active_nodes)
    to_active_nodes.update(state=NODE_STATES.ACTIVE)

    to_active_forever_nodes = Node.objects.filter(id__in=forever_nodes)
    to_active_forever_nodes.update(state=NODE_STATES.ACTIVE, scheduled=False)

    logger_params['activated_nodes'] = to_active_nodes.values_list('id', flat=True)
    logger_params['activated_forever_nodes'] = to_active_forever_nodes.values_list('id', flat=True)

    logger.info("Deleting schedules for forever nodes", params=logger_params)
    NodeScheduled.delete_schedules_for_nodes(forever_nodes)

    logger.info("Updating catalogs cache", params=logger_params)
    _update_node_shops_cache(to_active_nodes)
    _update_node_shops_cache(to_active_forever_nodes)
    logger.info("Successfully deactivated not in range nodes", params=logger_params)
    logger.info("Successfully activated in range nodes", params=logger_params)


def deactivate_not_in_range_nodes():
    """
    Take all the nodes that doesn't have a scheduled that is currently in range, but the nodes are active.
    Switch them to inactive.
    """
    logger.info("Deactivating not in range nodes")

    # Because using a subquery, we first need to get the
    # list of ids and then filter by the IDS. MySQL error 1093
    to_deactivate_nodes = list(Node.objects
                               .filter(id__in=RawSQL(SQL_GET_TO_DEACTIVATE_NODES, ()))
                               .values_list('id', flat=True))
    logger_params = dict(to_deactivate_nodes=to_deactivate_nodes)
    to_deactivate_nodes = Node.objects.filter(id__in=to_deactivate_nodes).all()
    logger.info("Got nodes to deactivate", params=logger_params)
    to_deactivate_nodes.update(state=NODE_STATES.INACTIVE)

    logger.info("Updating catalogs cache", params=logger_params)
    _update_node_shops_cache(to_deactivate_nodes)
    logger.info("Successfully deactivated not in range nodes", params=logger_params)


def delete_expired_schedules():
    """
    Delete expired schedules the their end date has passed already.
    """
    logger.info("Deleting expired unused schedules")
    # Because using a subquery, we first need to get the
    # list of ids and then filter by the IDS. MySQL error 1093
    old_schedules_ids = NodeScheduled.objects \
        .filter(id__in=RawSQL(SQL_GET_EXPIRED_SCHEDULES, ())) \
        .values_list('id', flat=True)
    old_schedules = NodeScheduled.objects.filter(id__in=list(old_schedules_ids)).all()
    old_schedules.delete()
    logger.info("Successfully deleted old unused schedules", params=dict(deleted_count=old_schedules.count()))


def remove_scheduled_flag_no_scheduled():
    """
    Set scheduled=False for nodes that doesn't have schedules.
    """
    logger.info("Starting to unschedule nodes without schedules")
    scheduled_nodes = Node.objects.filter(scheduled=True).select_related('node_schedules')
    scheduled_without_schedules = list(scheduled_nodes.annotate(scheduled_count=Count('node_schedules'))
                                       .filter(scheduled_count=0).values_list('id', flat=True))
    Node.objects.filter(id__in=scheduled_without_schedules).update(scheduled=False)
    logger.info("Finished to unschedule nodes without schedules",
                params=dict(node_ids=scheduled_without_schedules))


def update_all_scheduled_nodes():
    """
    Activates the needed nodes.
    Deactivates the needed nodes.
    Deletes old scheduled.
    :return:
    """
    logger.info("Starting to update all needed scheduled nodes")
    active_nodes, forever_nodes = _get_nodes_to_activate()
    activate_in_range_nodes(active_nodes, forever_nodes)
    deactivate_not_in_range_nodes()
    delete_expired_schedules()
    remove_scheduled_flag_no_scheduled()
    logger.info("Finished updating all needed scheduled nodes")


def _update_single_node(node):
    """
    Updates the node's status and it's catalog.
    :param node: The node to update.
    """
    node.update_node_according_to_range()
    catalog_changed(int(node.shop_id))




txtUserId = getRequestString("UserId");
txtSQL = "SELECT * FROM Users WHERE UserId = " + txtUserId;

uName = getRequestString("username");

uPass = getRequestString("userpassword");

sql = 'SELECT * FROM Users WHERE Name ="' + uName + '" AND Pass ="' + uPass + '"'

txtUserId = getRequestString("UserId");
txtSQL = "SELECT * FROM Users WHERE UserId = " + txtUserId;

txtUserId = getRequestString("UserId");
txtSQL = "SELECT * FROM Users WHERE UserId = @0";
db.Execute(txtSQL,txtUserId);

import sqlite3
import hashlib

from flask import Flask, request

app = Flask(__name__)


def connect():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    c = conn.cursor()
    c.execute("CREATE TABLE users (username TEXT, password TEXT, rank TEXT)")
    c.execute("INSERT INTO users VALUES ('admin', 'e1568c571e684e0fb1724da85d215dc0', 'admin')")
    c.execute("INSERT INTO users VALUES ('bob', '2b903105b59299c12d6c1e2ac8016941', 'user')")
    c.execute("INSERT INTO users VALUES ('alice', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'moderator')")

    c.execute("CREATE TABLE SSN(user_id INTEGER, number TEXT)")
    c.execute("INSERT INTO SSN VALUES (1, '480-62-10043')")
    c.execute("INSERT INTO SSN VALUES (2, '690-10-6233')")
    c.execute("INSERT INTO SSN VALUES (3, '401-09-1516')")

    conn.commit()
    return conn


CONNECTION = connect()


@app.route("/login")
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    md5 = hashlib.new('md5', password.encode('utf-8'))
    password = md5.hexdigest()
    c = CONNECTION.cursor()
    c.execute("SELECT * FROM users WHERE username = ? and password = ?", (username, password))
    data = c.fetchone()
    if data is None:
        return 'Incorrect username and password.'
    else:
        return 'Welcome %s! Your rank is %s.' % (username, data[2])


@app.route("/users")
def list_users():
    rank = request.args.get('rank', '')
    if rank == 'admin':
        return "Can't list admins!"
    c = CONNECTION.cursor()
    c.execute("SELECT username, rank FROM users WHERE rank = '{0}'".format(rank))
    data = c.fetchall()
    return str(data)


if __name__ == '__main__':
    app.run(debug=True)
secret = Eilon123!
