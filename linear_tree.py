import torch
import torch.nn as nn
from torch.autograd import Function



# Define Sparsemax function
class SparsemaxFunction(Function):
    @staticmethod
    def forward(ctx, input):
        # Sort input for sparsemax
        dim = -1
        input = input - input.max(dim=dim, keepdim=True)[0]
        zs = torch.sort(input, dim=dim, descending=True)[0]
        range = torch.arange(1, input.size(dim) + 1, device=input.device, dtype=input.dtype)
        range = range.view([1] * (input.dim() - 1) + [-1])
        cumsum_zs = zs.cumsum(dim=dim) - 1
        k = (range * zs > cumsum_zs).sum(dim=dim, keepdim=True)
        tau = cumsum_zs.gather(dim, k - 1) / k.to(input.dtype)
        output = torch.clamp(input - tau, min=0)
        ctx.save_for_backward(output)
        return output

    @staticmethod
    def backward(ctx, grad_output):
        output, = ctx.saved_tensors
        nonzero = output > 0
        sum_grad = (grad_output * nonzero).sum(dim=-1, keepdim=True)
        grad_input = nonzero * (grad_output - sum_grad / nonzero.sum(dim=-1, keepdim=True))
        return grad_input

# Define Sparsemax layer
class Sparsemax(nn.Module):
    def forward(self, input):
        return SparsemaxFunction.apply(input)

# Linear Tree Node
class LinearTreeNode(nn.Module):
    def __init__(self, input_dim):
        super(LinearTreeNode, self).__init__()
        self.linear = nn.Linear(input_dim, 1)
        self.sparsemax = Sparsemax()

    def forward(self, x):
        x = self.linear(x)
        return self.sparsemax(x)

# Linear Tree with trainable weights inside the absolute value differences
class LinearTree(nn.Module):
    def __init__(self, input_dim, num_nodes):
        super(LinearTree, self).__init__()
        self.nodes = nn.ModuleList([LinearTreeNode(input_dim) for _ in range(num_nodes)])
        
        # Trainable weights for individual feature differences
        self.weights = nn.ParameterDict({
            'w0': nn.Parameter(torch.randn(1)),
            'w2': nn.Parameter(torch.randn(1)),
            'w1': nn.Parameter(torch.randn(1)),
            'w4': nn.Parameter(torch.randn(1)),
            'w3': nn.Parameter(torch.randn(1)),
            'w5': nn.Parameter(torch.randn(1)),
            'w6': nn.Parameter(torch.randn(1)),
            'w9': nn.Parameter(torch.randn(1)),
        })
        
        self.leaf_linear = nn.Linear(input_dim, 1)  # Linear output for leaf

    def forward(self, x):
        # LAYER 1: SPARSEMAX/SPARSEMIN FUNCTION
        # Sum of weighted absolute differences between variable groups
        group_diffs = []
        # Compute weighted differences

        # west 
        diffw0 = torch.abs(x[:, 1] - x[:, 0])
        diffw1 = torch.abs(x[:, 2] - x[:, 1])
        diffw2 = torch.abs(x[:, 3] - x[:, 2])
        diffw3 = torch.abs(x[:, 4] - x[:, 3])

        diffw4 = torch.abs(x[:, 6] - x[:, 5])
        diffw5 = torch.abs(x[:, 7] - x[:, 6])
        diffw6 = torch.abs(x[:, 8] - x[:, 7])
        diffw7 = torch.abs(x[:, 9] - x[:, 8])

        diff4 = torch.abs(x[:, 11] - x[:, 10])
        diff4 = torch.abs(x[:, 12] - x[:, 11])
        diff4 = torch.abs(x[:, 13] - x[:, 12])



        # north west
        diffnw0 = torch.abs(x[:, 1] - x[:, 0])
        diffnw1 = torch.abs(x[:, 2] - x[:, 1])
        diffnw2 = torch.abs(x[:, 3] - x[:, 2])
        diffnw3 = torch.abs(x[:, 4] - x[:, 3])

        diffnw4 = torch.abs(x[:, 6] - x[:, 5])
        diffnw5 = torch.abs(x[:, 7] - x[:, 6])
        diffnw6 = torch.abs(x[:, 8] - x[:, 7])
        diffnw7 = torch.abs(x[:, 9] - x[:, 8])

        diffnw8 = torch.abs(x[:, 11] - x[:, 10])
        diffnw9 = torch.abs(x[:, 12] - x[:, 11])
        diffnwa = torch.abs(x[:, 13] - x[:, 12])

        
        # north
        diffn0 = torch.abs(x[:, 1] - x[:, 0])
        diffn1 = torch.abs(x[:, 2] - x[:, 1])
        diffn2 = torch.abs(x[:, 3] - x[:, 2])
        diffn3 = torch.abs(x[:, 4] - x[:, 3])

        diffn4 = torch.abs(x[:, 6] - x[:, 5])
        diffn5 = torch.abs(x[:, 7] - x[:, 6])
        diffn6 = torch.abs(x[:, 8] - x[:, 7])
        diffn7 = torch.abs(x[:, 9] - x[:, 8])

        diffn8 = torch.abs(x[:, 11] - x[:, 10])
        diffn9 = torch.abs(x[:, 12] - x[:, 11])
        diffna = torch.abs(x[:, 13] - x[:, 12])


        # northeast
        diffn0 = torch.abs(x[:, 1] - x[:, 0])
        diffn1 = torch.abs(x[:, 2] - x[:, 1])
        diffn2 = torch.abs(x[:, 3] - x[:, 2])
        diffn3 = torch.abs(x[:, 4] - x[:, 3])

        diffn4 = torch.abs(x[:, 6] - x[:, 5])
        diffn5 = torch.abs(x[:, 7] - x[:, 6])
        diffn6 = torch.abs(x[:, 8] - x[:, 7])
        diffn7 = torch.abs(x[:, 9] - x[:, 8])

        diffn8 = torch.abs(x[:, 11] - x[:, 10])
        diffn9 = torch.abs(x[:, 12] - x[:, 11])
        diffna = torch.abs(x[:, 13] - x[:, 12])






        # Group differences
        group0w  = diff1 + diff2
        group0nw = diff3 + diff4
        group0n  = diff3 + diff4
        group0ne = diff3 + diff4


        
        group_diffs.append(group1 + group2)



        # Apply Sparsemax to decide the path
        decisions = torch.stack(group_diffs, dim=-1)
        paths = self.nodes[0].sparsemax(decisions)


        # LAYER 2: SPARSEMAX FUNCTION


            
            # 1/2 between NORTHWEST and WEST
            # slope of 2 times west 1, 
                # minus west 2
                # minus north 1 west 2
            # slope of 2 times northwest
                # minus north 1 west 2
                # minus north 2 west 2
            # slope of 2 times northeast
                # minus north 1
                # minus north 2 
            cost = ABS(2*a-e-q) + ABS(2*c-q-s) + ABS(2*b-c-h) + ABS(2*d-b-f);
            
            # 1/2 between NORTHWEST and NORTH
            # slope of 2 times west 1
                # minus north 1 west 2
                # minus north 1 west 1
            # slope of 2 times northwest
                # minus north 2 west 2
                # minus north 2 west 1
            # slope of 2 times northeast
                # minus north 2
                # minus north 2 east 1
            cost = ABS(2*a-q-c) + ABS(2*c-s-h) + ABS(2*b-h-f) + ABS(2*d-f-g);
            
            # this is the 1/2 between NORTHEAST and NORTH
            # slope of 2 times west 1
                # minus northwest
                # minus north
            # slope of 2 times northwest
                # minus north 2 west 1
                # minus north 2
            # slope of 2 times northeast
                # minus north 2 east 1
                # minus north 2 east 2
            cost = ABS(2*a-c-b) + ABS(2*c-h-f) + ABS(2*b-f-g) + ABS(2*d-g-r);
            







        # LAYER 3: RELU FUNCTION
        relu()

        # Apply linear regression on leaf nodes
        leaf_output = self.leaf_linear(x)
        return paths * leaf_output

# Example usage
if __name__ == "__main__":
    # Sample data
    x = torch.randn(10, 10)  # 10 samples, 10 features

    # Initialize the tree
    tree = LinearTree(input_dim=10, num_nodes=3)

    # Forward pass
    output = tree(x)
    print(output)
