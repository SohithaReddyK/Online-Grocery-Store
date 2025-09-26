"use client"

import { useState } from "react"
import Link from "next/link"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { ChefHat, Clock, Search, User } from "lucide-react"
import { recipeData } from "@/data/recipes"

export default function SearchPage() {
  const [searchTerm, setSearchTerm] = useState("")
  const [searchResults, setSearchResults] = useState([])
  const [hasSearched, setHasSearched] = useState(false)

  // Function to perform search
  const performSearch = (term) => {
    if (!term.trim()) {
      setSearchResults([])
      setHasSearched(false)
      return
    }

    const normalizedTerm = term.toLowerCase().trim()

    const results = recipeData.filter(
      (recipe) =>
        recipe.title.toLowerCase().includes(normalizedTerm) ||
        recipe.description.toLowerCase().includes(normalizedTerm) ||
        recipe.category.toLowerCase().includes(normalizedTerm) ||
        (recipe.cuisine && recipe.cuisine.toLowerCase().includes(normalizedTerm)) ||
        // Search in ingredients if they exist
        (recipe.ingredients &&
          recipe.ingredients.some((ingredient) => ingredient.toLowerCase().includes(normalizedTerm))),
    )

    setSearchResults(results)
    setHasSearched(true)
  }

  const handleSearch = (e) => {
    e.preventDefault()
    performSearch(searchTerm)
  }

  // Handle search when user clicks on popular search terms
  const handlePopularSearch = (term) => {
    setSearchTerm(term)
    performSearch(term)
  }

  return (
    <div className="flex flex-col min-h-screen">
      <header className="sticky top-0 z-10 bg-white border-b">
        <div className="container flex items-center justify-between h-16 px-4 md:px-6">
          <Link href="/" className="flex items-center gap-2">
            <ChefHat className="w-6 h-6 text-orange-500" />
            <span className="text-xl font-bold">FoodPath</span>
          </Link>
          <div className="flex items-center gap-4">
            <Link href="/profile">
              <Button variant="ghost" size="icon">
                <User className="w-5 h-5" />
                <span className="sr-only">Profile</span>
              </Button>
            </Link>
          </div>
        </div>
      </header>
      <main className="flex-1">
        <div className="container px-4 py-8 md:px-6">
          <h1 className="text-3xl font-bold mb-6">Search Recipes</h1>
          <form onSubmit={handleSearch} className="flex gap-2 mb-8">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2.5 h-5 w-5 text-gray-500" />
              <Input
                type="search"
                placeholder="Search by recipe name, ingredients, or cuisine..."
                className="pl-10"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            <Button type="submit" className="bg-orange-500 hover:bg-orange-600">
              Search
            </Button>
          </form>

          {hasSearched && (
            <div>
              <h2 className="text-xl font-semibold mb-4">
                {searchResults.length > 0
                  ? `Found ${searchResults.length} results for "${searchTerm}"`
                  : `No results found for "${searchTerm}"`}
              </h2>

              {searchResults.length > 0 ? (
                <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                  {searchResults.map((recipe) => (
                    <Card key={recipe.id} className="overflow-hidden transition-transform hover:scale-[1.02]">
                      <div className="aspect-video relative">
                        <Image
                          src={recipe.image || "/placeholder.svg?height=200&width=300"}
                          alt={recipe.title}
                          fill
                          className="object-cover"
                          crossOrigin="anonymous"
                        />
                      </div>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className="px-2 py-1 text-xs font-medium rounded-full bg-orange-100 text-orange-800">
                            {recipe.category}
                          </span>
                          <div className="flex items-center text-gray-500">
                            <Clock className="w-4 h-4 mr-1" />
                            <span className="text-xs">{recipe.time} mins</span>
                          </div>
                        </div>
                        <h3 className="text-lg font-bold">{recipe.title}</h3>
                        <p className="mt-2 text-sm text-gray-600 line-clamp-2">{recipe.description}</p>
                      </CardContent>
                      <CardFooter className="p-4 pt-0">
                        <Link href={`/recipes/${recipe.id}`} className="w-full">
                          <Button className="w-full bg-orange-500 hover:bg-orange-600">View Recipe</Button>
                        </Link>
                      </CardFooter>
                    </Card>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12">
                  <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-orange-100 flex items-center justify-center">
                    <Search className="w-10 h-10 text-orange-500" />
                  </div>
                  <p className="text-gray-600">Try different keywords or browse our categories</p>
                  <Link href="/recipes" className="mt-6 inline-block">
                    <Button className="bg-orange-500 hover:bg-orange-600">Browse All Recipes</Button>
                  </Link>
                </div>
              )}
            </div>
          )}

          {!hasSearched && (
            <div className="grid gap-8">
              <div>
                <h2 className="text-xl font-semibold mb-4">Popular Searches</h2>
                <div className="flex flex-wrap gap-2">
                  {["Breakfast", "Dinner", "Vegetarian", "Quick", "Indian", "Italian", "Dessert", "Healthy"].map(
                    (term) => (
                      <Button key={term} variant="outline" onClick={() => handlePopularSearch(term)}>
                        {term}
                      </Button>
                    ),
                  )}
                </div>
              </div>

              <div>
                <h2 className="text-xl font-semibold mb-4">Trending Recipes</h2>
                <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                  {recipeData.slice(0, 4).map((recipe) => (
                    <Card key={recipe.id} className="overflow-hidden transition-transform hover:scale-[1.02]">
                      <div className="aspect-video relative">
                        <Image
                          src={recipe.image || "/placeholder.svg?height=200&width=300"}
                          alt={recipe.title}
                          fill
                          className="object-cover"
                          crossOrigin="anonymous"
                        />
                      </div>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className="px-2 py-1 text-xs font-medium rounded-full bg-orange-100 text-orange-800">
                            {recipe.category}
                          </span>
                          <div className="flex items-center text-gray-500">
                            <Clock className="w-4 h-4 mr-1" />
                            <span className="text-xs">{recipe.time} mins</span>
                          </div>
                        </div>
                        <h3 className="text-lg font-bold">{recipe.title}</h3>
                        <p className="mt-2 text-sm text-gray-600 line-clamp-2">{recipe.description}</p>
                      </CardContent>
                      <CardFooter className="p-4 pt-0">
                        <Link href={`/recipes/${recipe.id}`} className="w-full">
                          <Button className="w-full bg-orange-500 hover:bg-orange-600">View Recipe</Button>
                        </Link>
                      </CardFooter>
                    </Card>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
      <footer className="py-6 bg-orange-500 text-white">
        <div className="container px-4 md:px-6">
          <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
            <div className="flex items-center gap-2">
              <ChefHat className="w-6 h-6" />
              <span className="text-xl font-bold">FoodPath</span>
            </div>
            <p className="text-sm text-orange-100">© 2024 FoodPath. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
