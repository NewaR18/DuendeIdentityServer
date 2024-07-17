namespace Cinemas.Client.Helpers.Utilities
{
    public static class Message
    {
        #region Success
        public static string CreationSuccess = "Created Successfully!";
        public static string FetchSuccess = "Fetched Data Successfully!";
        public static string UpdateSuccess = "Updated Successfully!";
        public static string DeleteSuccess = "Deleted Successfully!";
        #endregion

        #region Failure
        public static string CreationFail = "Could not insert data";
        public static string FetchFail = "Problem while Fetching Data";
        public static string UpdateFail = "Could not update data";
        public static string DeleteFail = "Could not delete data";
        public static string IdNotPassed = "Id not passed";
        #endregion
    }
}
