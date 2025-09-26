"use client"

import { useState, use, useEffect } from "react"
import Link from "next/link"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { ChefHat, Clock, Heart, Share2, Star, User } from "lucide-react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { recipeData } from "@/data/recipes"
import { useToast } from "@/components/ui/use-toast"

export default function RecipeDetailPage({ params }) {
  // Unwrap the params object using React.use()
  const unwrappedParams = use(params)
  const recipeId = unwrappedParams.id

  const { toast } = useToast()
  const recipe = recipeData.find((r) => r.id === recipeId) || recipeData[0]
  const [activeTab, setActiveTab] = useState("instructions")
  const [rating, setRating] = useState(0)
  const [review, setReview] = useState("")
  const [reviews, setReviews] = useState(recipe.reviews || [])
  const [isSaved, setIsSaved] = useState(false)

  // Check if recipe is saved in localStorage on component mount
  useEffect(() => {
    const savedRecipes = JSON.parse(localStorage.getItem("savedRecipes") || "[]")
    setIsSaved(savedRecipes.some((saved) => saved.id === recipe.id))
  }, [recipe.id])

  const handleSubmitReview = (e) => {
    e.preventDefault()
    if (rating === 0 || !review.trim()) {
      toast({
        title: "Error",
        description: "Please provide both a rating and review text",
        variant: "destructive",
      })
      return
    }

    const newReview = {
      user: "You",
      rating,
      comment: review,
      date: new Date().toLocaleDateString(),
    }

    setReviews([newReview, ...reviews])
    setReview("")
    setRating(0)

    toast({
      title: "Success",
      description: "Review submitted successfully!",
    })
  }

  const toggleSaveRecipe = () => {
    // Get current saved recipes from localStorage
    const savedRecipes = JSON.parse(localStorage.getItem("savedRecipes") || "[]")

    if (isSaved) {
      // Remove recipe from saved recipes
      const updatedSavedRecipes = savedRecipes.filter((saved) => saved.id !== recipe.id)
      localStorage.setItem("savedRecipes", JSON.stringify(updatedSavedRecipes))
      setIsSaved(false)
      toast({
        title: "Recipe removed",
        description: "Recipe removed from your saved recipes",
      })
    } else {
      // Add recipe to saved recipes
      const recipeToSave = {
        id: recipe.id,
        title: recipe.title,
        description: recipe.description,
        image: recipe.image,
        category: recipe.category,
        time: recipe.time,
      }
      localStorage.setItem("savedRecipes", JSON.stringify([...savedRecipes, recipeToSave]))
      setIsSaved(true)
      toast({
        title: "Recipe saved",
        description: "Recipe added to your saved recipes",
      })
    }
  }

  // Ensure recipe has ingredients and instructions
  const ingredients = recipe.ingredients || ["This recipe's ingredients are not available"]

  const instructions = recipe.instructions || ["This recipe's instructions are not available"]

  return (
    <div className="flex flex-col min-h-screen">
      <header className="sticky top-0 z-10 bg-white border-b">
        <div className="container flex items-center justify-between h-16 px-4 md:px-6">
          <Link href="/" className="flex items-center gap-2">
            <ChefHat className="w-6 h-6 text-orange-500" />
            <span className="text-xl font-bold">FoodPath</span>
          </Link>
          <div className="flex items-center gap-4">
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
        <div className="container px-4 py-6 md:px-6">
          <div className="grid gap-6 md:grid-cols-2">
            <div className="relative aspect-video md:aspect-square overflow-hidden rounded-lg">
              <Image
                src={recipe.image || "/placeholder.svg?height=400&width=400"}
                alt={recipe.title}
                fill
                className="object-cover"
                crossOrigin="anonymous"
              />
            </div>
            <div className="space-y-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-1 text-xs font-medium rounded-full bg-orange-100 text-orange-800">
                    {recipe.category}
                  </span>
                  {recipe.cuisine && (
                    <span className="px-2 py-1 text-xs font-medium rounded-full bg-orange-100 text-orange-800">
                      {recipe.cuisine}
                    </span>
                  )}
                  <div className="flex items-center text-gray-500">
                    <Clock className="w-4 h-4 mr-1" />
                    <span className="text-xs">{recipe.time} mins</span>
                  </div>
                </div>
                <h1 className="text-3xl font-bold">{recipe.title}</h1>
                <div className="flex items-center mt-2">
                  {Array(5)
                    .fill(0)
                    .map((_, i) => (
                      <Star
                        key={i}
                        className={`w-5 h-5 ${i < recipe.rating ? "fill-orange-500 text-orange-500" : "text-gray-300"}`}
                      />
                    ))}
                  <span className="ml-2 text-sm text-gray-600">({reviews.length} reviews)</span>
                </div>
                <p className="mt-2 text-gray-600">{recipe.description}</p>
              </div>
              <div className="flex items-center gap-4">
                <Button
                  className={`${isSaved ? "bg-gray-500" : "bg-orange-500 hover:bg-orange-600"}`}
                  onClick={toggleSaveRecipe}
                >
                  <Heart className={`w-4 h-4 mr-2 ${isSaved ? "fill-white" : ""}`} />
                  {isSaved ? "Saved" : "Save Recipe"}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    navigator.clipboard.writeText(window.location.href)
                    toast({
                      title: "Link copied",
                      description: "Recipe link copied to clipboard",
                    })
                  }}
                >
                  <Share2 className="w-4 h-4 mr-2" />
                  Share
                </Button>
              </div>
              <div className="pt-4 border-t">
                <h3 className="mb-2 text-lg font-semibold">Ingredients</h3>
                <ul className="grid gap-2">
                  {ingredients.map((ingredient, index) => (
                    <li key={index} className="flex items-start gap-2">
                      <div className="w-1.5 h-1.5 mt-2 rounded-full bg-orange-500" />
                      <span>{ingredient}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
          <div className="mt-8">
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="w-full justify-start">
                <TabsTrigger value="instructions">Instructions</TabsTrigger>
                <TabsTrigger value="reviews">Reviews ({reviews.length})</TabsTrigger>
              </TabsList>
              <TabsContent value="instructions" className="mt-4">
                <Card>
                  <CardContent className="p-6">
                    <ol className="grid gap-6">
                      {instructions.map((step, index) => (
                        <li key={index} className="grid gap-2">
                          <div className="flex items-start gap-4">
                            <div className="flex items-center justify-center w-8 h-8 rounded-full bg-orange-100 text-orange-800 font-bold shrink-0">
                              {index + 1}
                            </div>
                            <p>{step}</p>
                          </div>
                        </li>
                      ))}
                    </ol>
                  </CardContent>
                </Card>
              </TabsContent>
              <TabsContent value="reviews" className="mt-4">
                <Card>
                  <CardContent className="p-6">
                    <div className="grid gap-6">
                      <div>
                        <h3 className="mb-4 text-lg font-semibold">Write a Review</h3>
                        <form onSubmit={handleSubmitReview} className="grid gap-4">
                          <div>
                            <div className="flex items-center gap-1 mb-2">
                              {[1, 2, 3, 4, 5].map((star) => (
                                <button
                                  key={star}
                                  type="button"
                                  onClick={() => setRating(star)}
                                  className="focus:outline-none"
                                >
                                  <Star
                                    className={`w-6 h-6 ${
                                      rating >= star ? "fill-orange-500 text-orange-500" : "text-gray-300"
                                    }`}
                                  />
                                </button>
                              ))}
                            </div>
                            <Textarea
                              placeholder="Share your experience with this recipe..."
                              value={review}
                              onChange={(e) => setReview(e.target.value)}
                              className="min-h-[100px]"
                            />
                          </div>
                          <Button type="submit" className="w-full sm:w-auto bg-orange-500 hover:bg-orange-600">
                            Submit Review
                          </Button>
                        </form>
                      </div>
                      <div className="grid gap-4">
                        <h3 className="text-lg font-semibold">User Reviews</h3>
                        {reviews.length > 0 ? (
                          reviews.map((review, index) => (
                            <div key={index} className="p-4 border rounded-lg">
                              <div className="flex items-center gap-2 mb-2">
                                <Avatar className="w-8 h-8">
                                  <AvatarImage src="/placeholder.svg?height=32&width=32" />
                                  <AvatarFallback>{review.user.charAt(0)}</AvatarFallback>
                                </Avatar>
                                <div>
                                  <div className="font-medium">{review.user}</div>
                                  <div className="flex">
                                    {Array(5)
                                      .fill(0)
                                      .map((_, i) => (
                                        <Star
                                          key={i}
                                          className={`w-4 h-4 ${
                                            i < review.rating ? "fill-orange-500 text-orange-500" : "text-gray-300"
                                          }`}
                                        />
                                      ))}
                                  </div>
                                </div>
                                {review.date && <div className="ml-auto text-xs text-gray-500">{review.date}</div>}
                              </div>
                              <p className="text-gray-600">{review.comment}</p>
                            </div>
                          ))
                        ) : (
                          <div className="text-center py-8 text-gray-500">
                            No reviews yet. Be the first to review this recipe!
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
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
