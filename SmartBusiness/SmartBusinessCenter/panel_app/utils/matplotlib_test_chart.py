import matplotlib.pyplot as plt

#Define data for the funnel chart

labels = ["Chart1","Chart2","Chart3","chart4","Chart5"]
values = [100,40,70,15,23]

#Calculate the cumulative values for plotting
cumulatives_values = [sum(values[:i+1]) for i in range(len(values))]

#Define colors for each segment
colors = ['blue','green','orange','red','purple']

#Create the funnel chart
fig, ax = plt.subplots()
for i in range (len(labels)):
    ax.fill_betweenx([i, i+ 1],0, cumulatives_values[i],step='mid',alpha=0.7, color=colors[i])

ax.set_yticks(range(len(labels)))
ax.set_yticklabels(labels)
ax.set_xlabel('Conversion Rate')

#Add Labels to the bars

for i, value in enumerate(cumulatives_values):
    ax.annotate(str(value), xy=(value,i), xytext=(5,5), textcoords='offset points')

plt.title('Funnel Chart')
plt.show()