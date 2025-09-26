"use client"

import type React from "react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { ShoppingCart, Search, LogOut, User } from "lucide-react"
import Link from "next/link"

const categories = [
  {
    name: "Snacks",
    icon: "🍿",
    image: "/colorful-snacks-chips-cookies-crackers.jpg",
  },
  {
    name: "Vegetables",
    icon: "🥕",
    image: "/fresh-vegetables-carrots-broccoli-tomatoes.jpg",
  },
  {
    name: "Fruits",
    icon: "🍎",
    image: "/fresh-fruits-apples-bananas-oranges.jpg",
  },
  {
    name: "Beverages",
    icon: "🥤",
    image: "/beverages-drinks-juice-soda-water.jpg",
  },
  {
    name: "Dairy Products",
    icon: "🥛",
    image: "/dairy-products-milk-cheese-yogurt.jpg",
  },
  {
    name: "Household Items",
    icon: "🧽",
    image: "/household-items-cleaning-supplies-detergent.jpg",
  },
]

export default function DashboardPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [cartCount, setCartCount] = useState(0)

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (searchQuery.toLowerCase().includes("milk")) {
      window.location.href = "/products/dairy-products"
    }
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-primary">GroceryStore</h1>
            </div>

            {/* Search Bar */}
            <form onSubmit={handleSearch} className="flex-1 max-w-lg mx-8">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                <Input
                  type="text"
                  placeholder="Search for products (try 'milk')"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 pr-4"
                />
              </div>
            </form>

            <div className="flex items-center space-x-4">
              <Link href="/cart">
                <Button variant="outline" size="sm" className="relative bg-transparent">
                  <ShoppingCart className="h-4 w-4 mr-2" />
                  Cart
                  {cartCount > 0 && (
                    <Badge className="absolute -top-2 -right-2 h-5 w-5 rounded-full p-0 flex items-center justify-center text-xs">
                      {cartCount}
                    </Badge>
                  )}
                </Button>
              </Link>

              {/* Updated Profile Button using Link */}
              <Link href="/profile">
                <Button variant="outline" size="sm">
                  <User className="h-4 w-4 mr-2" />
                  Profile
                </Button>
              </Link>

              <Button variant="outline" size="sm" onClick={() => (window.location.href = "/")}>
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-foreground mb-2">Shop by Category</h2>
          <p className="text-muted-foreground">Choose from our wide selection of fresh groceries</p>
        </div>

        {/* Categories Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {categories.map((category) => (
            <Link
              key={category.name}
              href={`/products/${category.name.toLowerCase().replace(" ", "-")}`}
            >
              <Card className="hover:shadow-lg transition-shadow cursor-pointer group">
                <CardHeader className="pb-4">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-xl group-hover:text-primary transition-colors">
                      {category.name}
                    </CardTitle>
                    <span className="text-2xl">{category.icon}</span>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="aspect-square rounded-lg overflow-hidden mb-4">
                    <img
                      src={category.image || "/placeholder.svg"}
                      alt={category.name}
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                    />
                  </div>
                  <CardDescription className="text-center">
                    Explore our fresh {category.name.toLowerCase()}
                  </CardDescription>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>

        {/* Featured Section */}
        <div className="mt-12">
          <h3 className="text-2xl font-bold text-foreground mb-6">Featured Deals</h3>
          <div className="bg-gradient-to-r from-primary/10 to-secondary/10 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-xl font-semibold mb-2">Fresh Produce Sale</h4>
                <p className="text-muted-foreground">
                  Get up to 30% off on fresh fruits and vegetables
                </p>
              </div>
              <Button>Shop Now</Button>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}