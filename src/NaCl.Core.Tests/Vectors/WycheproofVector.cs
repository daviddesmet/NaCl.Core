namespace NaCl.Core.Tests.Vectors
{
    using System;
    using System.Collections.Generic;

    public class WycheproofVector
    {
        public string Algorithm { get; set; }

        public Version GeneratorVersion { get; set; }

        public int NumberOfTests { get; set; }

        public object Header { get; set; }

        public List<TestGroup> TestGroups { get; set; }

        public class TestGroup
        {
            public int IvSize { get; set; }

            public int KeySize { get; set; }

            public int TagSize { get; set; }

            public string Type { get; set; }

            public List<Test> Tests { get; set; }

            public class Test
            {
                public int TcId { get; set; }

                public string Comment { get; set; }

                public string Key { get; set; }

                public string Iv { get; set; }

                public string Aad { get; set; }

                public string Msg { get; set; }

                public string Ct { get; set; }

                public string Tag { get; set; }

                public string Result { get; set; }

                public object Flags { get; set; }
            }
        }
    }
}