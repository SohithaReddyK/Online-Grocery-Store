"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { ChefHat, Clock, Search, Trash2, User } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"

export default function SavedRecipesPage() {
  const [savedRecipes, setSavedRecipes] = useState([])
  const { toast } = useToast()

  // Load saved recipes from localStorage on component mount
  useEffect(() => {
    const loadSavedRecipes = () => {
      const recipes = JSON.parse(localStorage.getItem("savedRecipes") || "[]")
      setSavedRecipes(recipes)
    }

    loadSavedRecipes()

    // Add event listener to update saved recipes if changed in another tab/component
    window.addEventListener("storage", loadSavedRecipes)

    return () => {
      window.removeEventListener("storage", loadSavedRecipes)
    }
  }, [])

  const removeRecipe = (id) => {
    const updatedRecipes = savedRecipes.filter((recipe) => recipe.id !== id)
    localStorage.setItem("savedRecipes", JSON.stringify(updatedRecipes))
    setSavedRecipes(updatedRecipes)

    // Dispatch storage event to notify other components
    window.dispatchEvent(new Event("storage"))

    toast({
      title: "Recipe removed",
      description: "Recipe removed from your saved recipes",
    })
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
            <Link href="/search">
              <Button variant="ghost" size="icon">
                <Search className="w-5 h-5" />
                <span className="sr-only">Search</span>
              </Button>
            </Link>
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
          <h1 className="mb-6 text-3xl font-bold">Saved Recipes</h1>
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {savedRecipes.map((recipe) => (
              <Card key={recipe.id} className="overflow-hidden">
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
                <CardFooter className="p-4 pt-0 flex justify-between">
                  <Link href={`/recipes/${recipe.id}`}>
                    <Button className="bg-orange-500 hover:bg-orange-600">View Recipe</Button>
                  </Link>
                  <Button variant="outline" size="icon" onClick={() => removeRecipe(recipe.id)}>
                    <Trash2 className="w-4 h-4 text-red-500" />
                    <span className="sr-only">Remove</span>
                  </Button>
                </CardFooter>
              </Card>
            ))}
          </div>
          {savedRecipes.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="w-24 h-24 mb-4 rounded-full bg-orange-100 flex items-center justify-center">
                <ChefHat className="w-12 h-12 text-orange-500" />
              </div>
              <h2 className="text-xl font-bold">No saved recipes yet</h2>
              <p className="mt-2 text-gray-600">Start saving your favorite recipes to access them quickly later</p>
              <Link href="/recipes" className="mt-6">
                <Button className="bg-orange-500 hover:bg-orange-600">Browse Recipes</Button>
              </Link>
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
