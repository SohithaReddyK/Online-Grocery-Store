"use client"

import React, { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import Link from "next/link"
import { useParams } from "next/navigation"

// ------- CONFIG: conversion rate (approximate) -------
const USD_TO_INR = 83 // change this number if you want a different conversion rate

const formatPrice = (usdPrice: number) => {
  const inr = usdPrice * USD_TO_INR
  return new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 2,
  }).format(inr)
}

// ------- Full productData (kept exactly from your pasted data) -------
const productData: Record<string, { id: number; name: string; price: number; image: string }[]> = {
  snacks: [
    { id: 1, name: "Potato Chips Classic", price: 2.99, image: "/potato-chips-bag.png" },
    { id: 2, name: "Chocolate Cookies", price: 4.49, image: "/chocolate-cookies.png" },
    { id: 3, name: "Mixed Nuts", price: 6.99, image: "/mixed-nuts-bowl.jpg" },
    { id: 4, name: "Granola Bars", price: 5.99, image: "/granola-energy-bars.jpg" },
    { id: 5, name: "Pretzels", price: 3.49, image: "/twisted-pretzels.jpg" },
    { id: 6, name: "Trail Mix", price: 7.99, image: "/trail-mix-nuts-dried-fruit.jpg" },
    { id: 7, name: "Popcorn", price: 2.79, image: "/placeholder-mzz7a.png" },
    { id: 8, name: "Crackers", price: 3.99, image: "/placeholder-sz34m.png" },
    { id: 9, name: "Cheese Puffs", price: 3.29, image: "/placeholder-d4a64.png" },
    { id: 10, name: "Beef Jerky", price: 8.99, image: "/placeholder-ui0sq.png" },
    { id: 11, name: "Rice Cakes", price: 4.29, image: "/placeholder-vg345.png" },
    { id: 12, name: "Fruit Gummies", price: 3.79, image: "/colorful-gummy-bears.jpg" },
    { id: 13, name: "Chocolate Bar", price: 2.49, image: "/placeholder-0nsg4.png" },
    { id: 14, name: "Peanut Butter Cups", price: 4.99, image: "/peanut-butter-cups.jpg" },
    { id: 15, name: "Tortilla Chips", price: 3.99, image: "/placeholder-lcqqs.png" },
    { id: 16, name: "Energy Bars", price: 6.49, image: "/placeholder-5u3mp.png" },
    { id: 17, name: "Dried Fruit", price: 5.79, image: "/placeholder-z41di.png" },
    { id: 18, name: "Protein Bars", price: 7.49, image: "/protein-bars-fitness.jpg" },
    { id: 19, name: "Veggie Chips", price: 4.79, image: "/placeholder-wylnf.png" },
    { id: 20, name: "Candy Mix", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
  ],
  vegetables: [
    { id: 21, name: "Fresh Carrots", price: 1.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 22, name: "Broccoli", price: 2.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 23, name: "Bell Peppers", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 24, name: "Spinach", price: 2.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 25, name: "Tomatoes", price: 3.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 26, name: "Onions", price: 1.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 27, name: "Potatoes", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 28, name: "Cucumber", price: 1.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 29, name: "Lettuce", price: 2.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 30, name: "Celery", price: 1.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 31, name: "Zucchini", price: 2.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 32, name: "Cauliflower", price: 3.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 33, name: "Green Beans", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 34, name: "Asparagus", price: 4.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 35, name: "Sweet Corn", price: 3.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 36, name: "Mushrooms", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 37, name: "Radishes", price: 1.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 38, name: "Kale", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 39, name: "Brussels Sprouts", price: 3.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 40, name: "Eggplant", price: 2.79, image: "/placeholder.svg?height=200&width=200" },
  ],
  fruits: [
    { id: 41, name: "Red Apples", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 42, name: "Bananas", price: 2.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 43, name: "Oranges", price: 4.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 44, name: "Strawberries", price: 5.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 45, name: "Grapes", price: 4.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 46, name: "Blueberries", price: 6.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 47, name: "Pineapple", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 48, name: "Mango", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 49, name: "Avocado", price: 1.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 50, name: "Lemons", price: 2.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 51, name: "Limes", price: 2.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 52, name: "Peaches", price: 4.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 53, name: "Pears", price: 3.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 54, name: "Cherries", price: 7.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 55, name: "Watermelon", price: 5.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 56, name: "Cantaloupe", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 57, name: "Kiwi", price: 4.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 58, name: "Raspberries", price: 6.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 59, name: "Blackberries", price: 6.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 60, name: "Plums", price: 4.29, image: "/placeholder.svg?height=200&width=200" },
  ],
  beverages: [
    { id: 61, name: "Orange Juice", price: 4.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 62, name: "Apple Juice", price: 4.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 63, name: "Sparkling Water", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 64, name: "Cola", price: 3.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 65, name: "Lemon Soda", price: 2.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 66, name: "Energy Drink", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 67, name: "Iced Tea", price: 3.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 68, name: "Coffee", price: 5.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 69, name: "Green Tea", price: 4.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 70, name: "Sports Drink", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 71, name: "Coconut Water", price: 3.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 72, name: "Cranberry Juice", price: 4.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 73, name: "Grape Juice", price: 4.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 74, name: "Lemonade", price: 3.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 75, name: "Mineral Water", price: 1.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 76, name: "Smoothie", price: 5.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 77, name: "Protein Shake", price: 6.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 78, name: "Kombucha", price: 4.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 79, name: "Almond Milk", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 80, name: "Soy Milk", price: 3.79, image: "/placeholder.svg?height=200&width=200" },
  ],
  "dairy-products": [
    { id: 81, name: "Whole Milk", price: 3.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 82, name: "2% Milk", price: 3.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 83, name: "Skim Milk", price: 3.19, image: "/placeholder.svg?height=200&width=200" },
    { id: 84, name: "Greek Yogurt", price: 5.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 85, name: "Cheddar Cheese", price: 4.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 86, name: "Mozzarella Cheese", price: 4.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 87, name: "Butter", price: 4.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 88, name: "Cream Cheese", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 89, name: "Sour Cream", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 90, name: "Heavy Cream", price: 3.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 91, name: "Cottage Cheese", price: 3.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 92, name: "Swiss Cheese", price: 5.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 93, name: "Parmesan Cheese", price: 7.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 94, name: "Vanilla Yogurt", price: 4.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 95, name: "Strawberry Yogurt", price: 4.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 96, name: "Ice Cream", price: 6.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 97, name: "Frozen Yogurt", price: 5.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 98, name: "Whipped Cream", price: 3.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 99, name: "Buttermilk", price: 2.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 100, name: "Goat Cheese", price: 6.49, image: "/placeholder.svg?height=200&width=200" },
  ],
  "household-items": [
    { id: 101, name: "Dish Soap", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 102, name: "Laundry Detergent", price: 8.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 103, name: "Paper Towels", price: 6.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 104, name: "Toilet Paper", price: 12.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 105, name: "All-Purpose Cleaner", price: 4.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 106, name: "Sponges", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 107, name: "Trash Bags", price: 7.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 108, name: "Aluminum Foil", price: 4.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 109, name: "Plastic Wrap", price: 3.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 110, name: "Fabric Softener", price: 5.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 111, name: "Glass Cleaner", price: 3.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 112, name: "Bleach", price: 2.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 113, name: "Air Freshener", price: 4.29, image: "/placeholder.svg?height=200&width=200" },
    { id: 114, name: "Disinfectant Wipes", price: 5.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 115, name: "Vacuum Bags", price: 6.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 116, name: "Light Bulbs", price: 8.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 117, name: "Batteries", price: 7.49, image: "/placeholder.svg?height=200&width=200" },
    { id: 118, name: "Rubber Gloves", price: 3.99, image: "/placeholder.svg?height=200&width=200" },
    { id: 119, name: "Scrub Brush", price: 2.79, image: "/placeholder.svg?height=200&width=200" },
    { id: 120, name: "Mop", price: 15.99, image: "/placeholder.svg?height=200&width=200" },
  ],
}

// ------- Component -------
export default function ProductsPage() {
  const params = useParams()
  const categoryParam = (params as any)?.category as string | undefined

  const [searchQuery, setSearchQuery] = useState("")
  const [cartCount, setCartCount] = useState(0)
  const [filteredProducts, setFilteredProducts] = useState<any[]>([])

  // If category param missing or invalid, show all products (flattened)
  const products =
    categoryParam && productData[categoryParam as keyof typeof productData]
      ? productData[categoryParam as keyof typeof productData]
      : Object.values(productData).flat()

  const categoryName = categoryParam
    ? (categoryParam?.replace("-", " ").replace(/\b\w/g, (l) => l.toUpperCase()) || "Products")
    : "All Products"

  // filter when search or products change
  useEffect(() => {
    if (searchQuery) {
      const filtered = products.filter((product) =>
        product.name.toLowerCase().includes(searchQuery.toLowerCase())
      )
      setFilteredProducts(filtered)
    } else {
      setFilteredProducts(products)
    }
  }, [searchQuery, products])

  // cart logic (localStorage)
  const addToCart = (product: any) => {
    const existingCart = JSON.parse(localStorage.getItem("cart") || "[]")
    const existingItem = existingCart.find((item: any) => item.id === product.id)

    if (existingItem) {
      existingItem.quantity += 1
    } else {
      // keep original USD price in data but display using formatPrice everywhere
      existingCart.push({ ...product, quantity: 1 })
    }

    localStorage.setItem("cart", JSON.stringify(existingCart))
    setCartCount(existingCart.reduce((total: number, item: any) => total + item.quantity, 0))
  }

  useEffect(() => {
    const existingCart = JSON.parse(localStorage.getItem("cart") || "[]")
    setCartCount(existingCart.reduce((total: number, item: any) => total + item.quantity, 0))
  }, [])

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Link href="/dashboard">
                <Button variant="ghost" size="sm" className="mr-4">
                  ← Back
                </Button>
              </Link>
              <h1 className="text-2xl font-bold text-primary">GroceryStore</h1>
            </div>

            {/* Search Bar */}
            <div className="flex-1 max-w-lg mx-8">
              <div className="relative">
                <span className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground text-sm">
                  🔍
                </span>
                <Input
                  type="text"
                  placeholder={`Search in ${categoryName}...`}
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 pr-4"
                />
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <Link href="/cart">
                <Button variant="outline" size="sm" className="relative bg-transparent">
                  🛒 Cart
                  {cartCount > 0 && (
                    <Badge className="absolute -top-2 -right-2 h-5 w-5 rounded-full p-0 flex items-center justify-center text-xs">
                      {cartCount}
                    </Badge>
                  )}
                </Button>
              </Link>
              <Button variant="outline" size="sm">
                👤 Profile
              </Button>
              <Button variant="outline" size="sm" onClick={() => (window.location.href = "/")}>
                🚪 Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-foreground mb-2">{categoryName}</h2>
          <p className="text-muted-foreground">
            {filteredProducts.length} products available {searchQuery && `matching "${searchQuery}"`}
          </p>
        </div>

        {/* Products Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-6">
          {filteredProducts.map((product) => (
            <Card key={product.id} className="hover:shadow-lg transition-shadow">
              <CardContent className="p-4">
                <div className="aspect-square rounded-lg overflow-hidden mb-4 bg-muted">
                  <img
                    src={product.image || "/placeholder.svg"}
                    alt={product.name}
                    className="w-full h-full object-cover"
                  />
                </div>
                <h3 className="font-semibold text-sm mb-2 line-clamp-2">{product.name}</h3>
                <div className="flex items-center justify-between">
                  <span className="text-lg font-bold text-primary">
                    {formatPrice(product.price)}
                  </span>
                  <Button size="sm" onClick={() => addToCart(product)} className="text-xs px-3">
                    + Add to Cart
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {filteredProducts.length === 0 && searchQuery && (
          <div className="text-center py-12">
            <p className="text-muted-foreground text-lg">No products found matching "{searchQuery}"</p>
            <Button variant="outline" className="mt-4 bg-transparent" onClick={() => setSearchQuery("")}>
              Clear Search
            </Button>
          </div>
        )}
      </main>
    </div>
  )
}
