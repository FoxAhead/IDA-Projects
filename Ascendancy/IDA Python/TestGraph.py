from dataclasses import dataclass

import networkx as nx
import matplotlib.pyplot as plt


def main():
    e = 0x2106C
    r = [(0, 1), (1, 2), (2, 2), (1, 3), (2, 3), (3, 4), (6, 5), (8, 5), (4, 6), (5, 6), (6, 7), (9, 8), (10, 8), (11, 8), (7, 9), (8, 9), (9, 10), (10, 11), (3, 12), (5, 12)]

    e = 0x1F038
    r = [(0, 1), (1, 2), (1, 3), (3, 4), (3, 5), (9, 6), (5, 7), (6, 7), (7, 8), (8, 9), (10, 9), (9, 10), (7, 11), (11, 12), (11, 13), (15, 14), (13, 15), (14, 15), (15, 16), (20, 17), (16, 18), (17, 18), (18, 19), (19, 20), (19, 21), (20, 21), (18, 22), (22, 23), (26, 23), (23, 24), (23, 25),
         (24, 26), (25, 26), (22, 27), (26, 27), (27, 28), (28, 29), (39, 29), (29, 30), (29, 31), (31, 32), (32, 33), (38, 33), (36, 34), (33, 35), (34, 35), (35, 36), (36, 37), (35, 38), (37, 38), (31, 39), (38, 39), (27, 40), (39, 40)]

    # 1D794
    # r = [(0, 1), (5, 2), (10, 2), (11, 2), (14, 2), (1, 3), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7), (7, 8), (6, 9), (7, 9), (8, 9), (8, 10), (9, 10), (10, 11), (9, 12), (11, 12), (12, 13), (12, 14), (13, 14), (3, 15), (4, 15), (15, 16)]

    G = nx.DiGraph()
    G.add_edges_from(r)
    #nx.write_graphml_lxml(G, "D:\graph_%.X.graphml" % e)
    # subax1 = plt.subplot(121)
    # nx.draw(G, with_labels=True, font_weight='bold', arrowsize=15)
    nx.draw(G, with_labels=True, font_weight='bold', arrowsize=15)
    # plt.show()
    # G2 = nx.DiGraph()
    # G2.add_edges_from(r)
    # subax2 = plt.subplot(122)
    # nx.draw_spring(G2, with_labels=True, font_weight='bold')

    # plt.show()

    cycles = list(nx.simple_cycles(G))
    print(cycles)
    for node in G.nodes:
        if not any(node in cycle for cycle in cycles):
#        if not node_in_cycles(node, cycles):
            for succ in G.successors(node):
                for cycle in cycles:
                    if succ in cycle:
                        while cycle[0] != succ:
                            cycle = rotate(cycle, 1)
                        print("%d -> %s" % (node, cycle))


def rotate(l, n):
    return l[n:] + l[:n]


def node_in_cycles(node, cycles):
    for cycle in cycles:
        if node in cycle:
            return True
    return False


if __name__ == '__main__':
    main()
