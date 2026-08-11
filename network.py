import matplotlib.pyplot as plt
import networkx as nx


def generate_propagation_graph(source_nodes, target_node="Target Upload"):
    plt.close("all")

    G = nx.DiGraph()

    for src, dst in source_nodes:
        G.add_edge(src, dst)

    fig, ax = plt.subplots(figsize=(7, 4.5))

    pos = nx.spring_layout(G, seed=42)

    node_colors = []
    for node in G.nodes():
        if node == target_node:
            node_colors.append("#ff4b4b")
        elif G.in_degree(node) == 0:
            node_colors.append("#21c35e")
        else:
            node_colors.append("#00d4b1") 

    nx.draw_networkx_nodes(
        G, pos, ax=ax, node_color=node_colors, node_size=2200, alpha=0.9
    )
    nx.draw_networkx_edges(
        G,
        pos,
        ax=ax,
        edge_color="#888888",
        arrows=True,
        arrowsize=20,
        width=1.8,
    )
    nx.draw_networkx_labels(
        G, pos, ax=ax, font_size=9, font_weight="bold", font_color="#111111"
    )

    ax.set_title("Media Propagation Chain", fontsize=12, fontweight="bold")
    ax.axis("off")
    fig.tight_layout()

    return fig