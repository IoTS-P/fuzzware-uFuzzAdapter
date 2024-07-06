import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.legend_handler import HandlerBase

class HandlerCircleWithBackground(HandlerBase):
    def __init__(self, facecolor, edgecolor, radius=5):
        self.facecolor = facecolor
        self.edgecolor = edgecolor
        self.radius = radius
        super().__init__()

    def create_artists(self, legend, orig_handle, xdescent, ydescent, width, height, fontsize, trans):
        # Center the circle
        r = self.radius
        x = width / 2
        y = height / 2

        # Create a shadow/background
        shadow = mpatches.Circle((x, y), radius=r * 1.2, color=self.edgecolor, alpha=0.3, transform=trans)

        # Create the main circle
        circle = mpatches.Circle((x, y), radius=r, color=self.facecolor, transform=trans)

        return [shadow, circle]

# Set up the figure and axis
fig, ax = plt.subplots()

# Define the data for the legend
data = [
    ('Fuzzware', 'pink', 'lightpink'),
    ('Ember-IO', 'green', 'lightgreen'),
    ('MultiFuzz (Ours)', 'blue', 'lightblue')
]

# Map for custom handlers
handler_map = {}

# Create a list for handles
legend_handles = []

for label, color, shadow in data:
    # Create a patch as a proxy artist
    patch = mpatches.Circle((0.5, 0.5), 0.1, facecolor=color, edgecolor='none')
    # Store the handler with its custom colors
    handler_map[patch] = HandlerCircleWithBackground(color, shadow)
    # Append the patch to the handles list
    legend_handles.append(patch)

# Create the legend
ax.legend(handles=legend_handles, labels=[d[0] for d in data], handler_map=handler_map, loc='upper left')

# Display the plot
plt.show()
plt.savefig('legend.png')