"use client"

import { use } from "react"
import Link from "next/link"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { ChefHat, Clock, Heart, Search, User } from "lucide-react"
import { recipeData } from "@/data/recipes"

export default function CuisinePage({ params }) {
  // Unwrap the params object using React.use()
  const unwrappedParams = use(params)
  const cuisine = unwrappedParams.cuisine

  const formattedCuisine = cuisine.charAt(0).toUpperCase() + cuisine.slice(1)

  const cuisineRecipes = recipeData.filter(
    (recipe) => recipe.cuisine && recipe.cuisine.toLowerCase() === cuisine.toLowerCase(),
  )

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
            <Link href="/saved-recipes">
              <Button variant="ghost" size="icon">
                <Heart className="w-5 h-5" />
                <span className="sr-only">Saved Recipes</span>
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
          <div className="flex items-center justify-between mb-6">
            <h1 className="text-3xl font-bold">{formattedCuisine} Cuisine</h1>
            <Link href="/recipes">
              <Button variant="outline">All Recipes</Button>
            </Link>
          </div>

          {cuisineRecipes.length > 0 ? (
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {cuisineRecipes.map((recipe) => (
                <Card key={recipe.id} className="overflow-hidden transition-transform hover:scale-[1.02]">
                  <div className="aspect-video relative">
                    <Image
                      src={recipe.image || "/placeholder.svg"}
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
                <ChefHat className="w-10 h-10 text-orange-500" />
              </div>
              <h2 className="text-xl font-bold">No recipes found</h2>
              <p className="mt-2 text-gray-600">We couldn't find any {formattedCuisine} recipes</p>
              <Link href="/recipes" className="mt-6 inline-block">
                <Button className="bg-orange-500 hover:bg-orange-600">Browse All Recipes</Button>
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
