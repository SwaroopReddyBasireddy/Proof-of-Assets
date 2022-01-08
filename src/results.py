import numpy as np
import matplotlib.pyplot as plt

constr_time = np.array([2.6894, 24.6522, 243.994, 2438.84, 24394.6])
#print(constr_time/60.0)

n = np.array([10, 100, 1000, 10000, 100000])

ver_time = np.array([0.050278, 0.460322, 4.57224, 45.6051, 467.268])

proof_size = np.array([0.016841, 0.154631, 1.53253, 15.3115, 153.102])

# plt.plot(n,constr_time/60.0,label = "proof construction time" )
# plt.plot(n,ver_time/60.0,label = "proof verification time" )
# plt.xlabel("Anonymity set size (n)")
# plt.ylabel("Time (minutes)")
# plt.legend(loc = 2)
# plt.grid()
# plt.show()


fig = plt.figure()
ax1 = fig.add_subplot(111)
ax1.plot(n,constr_time/60.0, 'b', label = "Proof generation time")
ax1.plot(n,ver_time/60.0, 'm-', label = "Proof verification time")
ax1.set_ylabel('Time in Minutes')
ax1.set_ylim(-10,500)
ax2 = ax1.twinx()
ax2.plot(n, proof_size, 'y-', label = "Proof size")
ax2.set_ylabel('Size in MB')
ax1.set_xlabel('Anonymity set size $n$')
ax2.set_ylim(-5,225)
#for tl in ax2.get_yticklabels():
#    tl.set_color('r')
    
ax1.legend(loc=2)
ax2.legend(loc=1)
  
# Sdding grid
ax1.grid()
plt.savefig('results.eps')
plt.savefig('results.pdf')
plt.show()

print(constr_time/60.0)
print(ver_time/60.0)

