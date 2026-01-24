document.addEventListener("DOMContentLoaded", () => {
    const cart = [];
    const searchToggle = document.getElementById("search-toggle");
    const searchBox = document.getElementById("search-box");
    const cartIcon = document.getElementById("cart-icon");
    const sidebar = document.getElementById("sidebar");
    const closeIcon = document.querySelector(".sider-close");
    const cartItems = document.querySelector(".cart-items");
    const cartTotal = document.querySelector(".cart-total");
    const checkoutButton = document.querySelector(".checkout");
    const inputBox = document.getElementById("input-box");
    const resultBox = document.querySelector(".result-box");
    const menuIcon = document.querySelector('.menu-icon');
    let totalAmount = 0; // Total amount in the cart

    // Search toggle functionality
    if (searchToggle) {
        searchToggle.addEventListener("click", () => {
            searchBox.classList.toggle("active");
        });
    }

    // Cart icon functionality (open sidebar)
    if (cartIcon) {
        cartIcon.addEventListener("click", () => {
            sidebar.style.right = "0";
        });
    }

    // Close icon functionality (close sidebar)
    if (closeIcon) {
        closeIcon.addEventListener("click", () => {
            sidebar.style.right = "-100%";
        });
    }

    // Function to toggle menu dropdown
    function toggleMenu() {
        const dropdownMenu = document.getElementById("dropdownMenu");
        dropdownMenu.style.display = (dropdownMenu.style.display === "none" || dropdownMenu.style.display === "") ? "block" : "none";
    }

    if (menuIcon) {
        menuIcon.addEventListener('click', toggleMenu);
    }

    // Function to update cart display
    function updateCartDisplay() {
        const cartItemsContainer = document.querySelector('.cart-items');
        cartItemsContainer.innerHTML = ''; // Clear current items
        totalAmount = 0; // Reset total amount

        cart.forEach((item, index) => {
            const itemElement = document.createElement('div');
            itemElement.classList.add("cart-item");
            itemElement.innerHTML = `
                ${item.name} - ₹${item.price.toFixed(2)} x ${item.quantity}
                <button class="remove-item">✖</button>
            `;
            cartItemsContainer.appendChild(itemElement);

            // Add event listener for remove button
            const removeButton = itemElement.querySelector('.remove-item');
            removeButton.addEventListener('click', () => {
                removeOneFromCart(index);
            });

            // Update total
            totalAmount += item.price * item.quantity;
        });

        // Display total amount
        document.querySelector('.cart-total').textContent = `₹${totalAmount.toFixed(2)}`;
        document.querySelector('.quantity').textContent = cart.length;
    }

    // Function to add items to the cart
    function addToCart(item) {
        const existingItem = cart.find(cartItem => cartItem.name === item.name);

        if (existingItem) {
            existingItem.quantity += 1; // If item exists, increase quantity
        } else {
            cart.push({ ...item, quantity: 1 }); // Add new item with quantity 1
        }

        updateCartDisplay(); // Recalculate and update display after adding item
    }

    // Function to remove one item from the cart (decrease quantity by 1)
    function removeOneFromCart(index) {
        const item = cart[index];
        if (item.quantity > 1) {
            item.quantity -= 1; // Decrease quantity by 1
        } else {
            cart.splice(index, 1); // Remove the item completely if quantity is 1
        }

        updateCartDisplay(); // Re-render the cart display and update total amount
    }

    // Add event listeners to add-to-cart buttons
    document.querySelectorAll('.btn button').forEach((button) => {
        button.addEventListener('click', () => {
            const card = button.closest('.card');
            const itemName = card.querySelector('.card-title').textContent;
            const itemPrice = parseFloat(card.querySelector('.card-price span').textContent.replace('₹', ''));

            addToCart({ name: itemName, price: itemPrice }); // Add item to the cart
        });
    });

    // Cart sidebar open/close toggle
    if (cartIcon) {
        cartIcon.addEventListener('click', () => {
            sidebar.style.display = sidebar.style.display === 'block' ? 'none' : 'block';
        });
    }

    // Checkout button functionality
    if (checkoutButton) {
        checkoutButton.addEventListener("click", () => {
            localStorage.setItem("cart", JSON.stringify(cart));
            localStorage.setItem("totalAmount", totalAmount.toFixed(2));
            window.location.href = "checkout.html"; // Navigate to checkout page
        });
    }

    // Initial cart display update
    updateCartDisplay();
});
