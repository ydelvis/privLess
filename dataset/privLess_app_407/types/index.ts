// ==================================================================
// id
// ==================================================================

type PostId = string;
type PublicationId = string;
type TagId = string;
type CategoryId = string;
type AuthorId = string;

// ==================================================================
// models
// ==================================================================

export interface Post {
  id: string;
  title: string;
  summary: string;
  thumbnail?: string;
  body: PostBody;
  cover?: string;
  tags: TagLike[];
  isDraft: boolean;
  category: CategoryLike;
  slug: string;
  visibility?: PostVisibility;
  scheduledAt?: Date;
  createdAt: Date;
  postedAt?: Date;
  /**
   * locale code
   * e.g. en-us
   */
  locale?: String;
  author?: AuthorLike;
  publicationId: PublicationId;
}

export enum PostVisibility {
  public = "public",
  private = "private",
  password = "password_protected",
}

export interface Publication {}
export interface PostBody {}
export interface PostAsset {}

// ==================================================================
// dto
// ==================================================================

export interface PostSummary {
  id: string;
  title: string;
  summary: string;
  thumbnail?: string;
  tags?: TagLike[];
  isDraft: boolean;
  category: CategoryLike;
  createdAt: Date;
  postedAt?: Date;
  locale?: String;
  author?: AuthorLike;
}

export type Tag = {
  id: TagId | "\\none\\";
  name: string;
};

export type Category = {
  id: CategoryId;
  name: string;
};

export type TagLike = Tag | string;
export type TagReferenceLike = TagId | string;
export type CategoryLike = "\\default\\" | Category | string;
export type CategoryReferenceLike = "\\default\\" | CategoryId | string;
export type AuthorLike = {
  id: AuthorId;
  name: string;
  avatar?: string;
};

// ==================================================================
// responses
// ==================================================================

export type Actions =
  | CreateDraftPostRequest
  | UpdatePostBodyRequest
  | CreateAssetRequest
  | UpdatePostTagsRequest
  | UpdatePostTitleRequest
  | UpdatePostThumbnailRequest
  | UpdatePostCategoryRequest
  | UpdatePostScheduleRequest;

export type CreateDraftPostRequest = {
  type: "create-draft-post";
};

export type UpdatePostRequest = {
  type: "update-post";
} & Post;

export type UpdatePostBodyRequest = {
  type: "update-post-body";
  id: PostId;
  body: PostBody;
};

export type CreateAssetRequest = {
  type: "create-asset";
  post: PostId;
  asset: PostAsset;
};

export type UpdatePostTagsRequest = {
  type: "update-post-tags";
  id: PostId;
  tags: ReadonlyArray<TagReferenceLike>;
};

export type UpdatePostTitleRequest = {
  type: "update-post-title";
  id: PostId;
  title: string;
};

export type UpdatePostThumbnailRequest = {
  type: "update-post-thumbnail";
  id: PostId;
  asset: PostAsset;
};

export type UpdatePostCategoryRequest = {
  type: "update-post-category";
  id: PostId;
  category: CategoryReferenceLike;
};

export type UpdatePostScheduleRequest =
  | {
      type: "update-post-schedule";
      id: PostId;
      date: Date;
    }
  | {
      type: "remove-post-schedule";
      id: PostId;
      and: "publish-now" | "mark-as-draft";
    };

// ==================================================================
// responses
// ==================================================================

export type UpdatePostScheduleResponse =
  | {
      error: string;
    }
  | {
      id: PostId;
      date: Date;
      success: true;
    };

export type GetPostResponse = Post;
export type GetPostTagsResponse = ReadonlyArray<Tag>;
export type GetPostCategoryResponse = Category;
export type GetPostsResponse = ReadonlyArray<PostSummary>;
export type GetUnlistedPostsResponse = ReadonlyArray<PostSummary>;
export type GetDraftPostsResponse = ReadonlyArray<PostSummary>;
export type GetPostAssetsResponse = ReadonlyArray<PostAsset>;
