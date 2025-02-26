import random
import matplotlib.pyplot as plt

def simulate_comcom_stock(days=365, initial_price=62, seed=None):
    """
    Perform a single-run Monte Carlo simulation of ComCom's stock price
    over `days` days, starting from `initial_price`.
    
    Returns:
        A list of daily stock prices (length = days+1, including day 0).
    """
    if seed is not None:
        random.seed(seed)  # for reproducibility

    # 1) Direction probabilities
    directions = ["Increase", "Same", "Decrease"]
    dir_probs  = [0.45, 0.30, 0.25]

    # 2) Magnitude distribution for INCREASE
    inc_fracs = [1/8, 1/4, 3/8, 1/2, 5/8, 3/4, 7/8, 1.0]
    inc_probs = [0.40, 0.17, 0.12, 0.10, 0.08, 0.07, 0.04, 0.02]

    # 3) Magnitude distribution for DECREASE
    dec_fracs = [1/8, 1/4, 3/8, 1/2, 5/8, 3/4, 7/8, 1.0]
    dec_probs = [0.12, 0.15, 0.18, 0.21, 0.14, 0.10, 0.05, 0.05]

    # Initialize
    price = initial_price
    price_path = [price]  # store price for day 0

    # Simulation loop
    for _ in range(days):
        # Choose direction
        move = random.choices(directions, dir_probs)[0]

        if move == "Same":
            # No change
            price_path.append(price)
            continue

        elif move == "Increase":
            frac = random.choices(inc_fracs, inc_probs)[0]
            if frac == 1.0:
                # Double the price
                price *= 2
            else:
                price *= (1 + frac)
            price_path.append(price)

        else:  # move == "Decrease"
            frac = random.choices(dec_fracs, dec_probs)[0]
            if frac == 1.0:
                # Price goes to zero
                price = 0
            else:
                price *= (1 - frac)
            price_path.append(price)

    return price_path


if __name__ == "__main__":
    # Set simulation parameters:
    days_to_simulate = 365
    starting_price = 62
    
    # Run the simulation
    simulated_prices = simulate_comcom_stock(days=days_to_simulate, 
                                             initial_price=starting_price, 
                                             seed=42)
    
    # Print final result
    print(f"Final stock price after {days_to_simulate} days: {simulated_prices[-1]:.2f}")

    # Plot the simulated path
    plt.figure(figsize=(8,4))
    plt.plot(simulated_prices, marker='o', markersize=3, linewidth=1)
    plt.title("ComCom Stock Price Simulation Over 1 Year")
    plt.xlabel("Day")
    plt.ylabel("Price")
    plt.grid(True)
    plt.show()