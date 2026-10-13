import os
import shutil
import tempfile
import unittest

from siftlog.ingest import MAX_LINE_BYTES, TailReader, file_identity, iter_file_lines

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sshd_real_format.log")


class TailTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.path = os.path.join(self.dir, "auth.log")

    def write(self, data, mode="ab", path=None):
        with open(path or self.path, mode) as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())

    def texts(self, lines):
        return [text for _, _, text in lines]


class FollowTests(TailTestCase):
    def test_returns_only_what_is_new(self):
        self.write("one\ntwo\n")
        reader = TailReader(self.path)
        self.assertEqual([(o, t) for _, o, t in reader.poll()], [(0, "one"), (4, "two")])
        self.assertEqual(reader.poll(), [])
        self.write("three\n")
        self.assertEqual([(o, t) for _, o, t in reader.poll()], [(8, "three")])
        self.assertEqual(reader.offset, 14)

    def test_same_offsets_and_identity_as_the_batch_reader(self):
        shutil.copy(FIXTURE, self.path)
        reader = TailReader(self.path)
        lines = reader.poll()
        self.assertEqual([(o, t) for _, o, t in lines], list(iter_file_lines(self.path)))
        self.assertEqual({sid for sid, _, _ in lines}, {file_identity(self.path)})

    def test_a_line_still_being_written_waits(self):
        self.write("one\npart")
        reader = TailReader(self.path)
        self.assertEqual(self.texts(reader.poll()), ["one"])
        self.assertEqual(reader.poll(), [])
        self.write("ial\n")
        self.assertEqual([(o, t) for _, o, t in reader.poll()], [(4, "partial")])

    def test_nothing_until_the_first_line_is_complete(self):
        # The stream is identified by its first line, so that line must be whole first.
        self.write("abc")
        reader = TailReader(self.path)
        self.assertEqual((reader.poll(), reader.source_id), ([], None))
        self.write("def\n")
        (line,) = reader.poll()
        self.assertEqual(line, (file_identity(self.path), 0, "abcdef"))

    def test_a_file_that_does_not_exist_yet(self):
        reader = TailReader(self.path)
        self.assertEqual(reader.poll(), [])
        self.write("hello\n")
        self.assertEqual(self.texts(reader.poll()), ["hello"])

    def test_crlf_and_invalid_utf8(self):
        self.write(b"one\r\nbad \xff byte\r\n")
        self.assertEqual(self.texts(TailReader(self.path).poll()), ["one", "bad � byte"])


class RotationTests(TailTestCase):
    def test_rename_rotation_loses_nothing(self):
        self.write("old 1\nold 2\n")
        reader = TailReader(self.path)
        reader.poll()
        old_id = reader.source_id
        self.write("old 3, written just before rotation\n")
        os.rename(self.path, self.path + ".1")
        self.write("new 1\n", mode="wb")

        lines = reader.poll()
        self.assertEqual(self.texts(lines), ["old 3, written just before rotation", "new 1"])
        self.assertEqual(lines[0][0], old_id)
        self.assertNotEqual(lines[1][0], old_id)
        self.assertEqual((lines[1][1], reader.source_id), (0, file_identity(self.path)))

    def test_keeps_reading_the_old_file_until_a_new_one_appears(self):
        self.write("old 1\n")
        reader = TailReader(self.path)
        reader.poll()
        os.rename(self.path, self.path + ".1")
        self.assertEqual(reader.poll(), [])
        self.write("old 2\n", path=self.path + ".1")  # the writer still has the old file open
        self.assertEqual(self.texts(reader.poll()), ["old 2"])
        self.write("new 1\n", mode="wb")
        self.assertEqual(self.texts(reader.poll()), ["new 1"])

    def test_truncation_in_place_starts_a_new_stream(self):
        self.write("first line of the old log\nsecond\nthird\n")
        reader = TailReader(self.path)
        reader.poll()
        old_id = reader.source_id
        self.write("fresh\n", mode="wb")  # copytruncate: same file, emptied and written again
        (line,) = reader.poll()
        self.assertEqual(line[1:], (0, "fresh"))
        self.assertNotEqual(line[0], old_id)

    def test_truncation_that_keeps_the_same_first_line(self):
        # The first line is unchanged, so only the file having shrunk gives it away.
        # Without that check the reader would sit beyond the end, reading nothing.
        self.write("same first line\nsecond\nthird\n")
        reader = TailReader(self.path)
        reader.poll()
        self.write("same first line\n", mode="wb")
        self.assertEqual([(o, t) for _, o, t in reader.poll()], [(0, "same first line")])
        self.write("new second\n")
        self.assertEqual([(o, t) for _, o, t in reader.poll()], [(16, "new second")])

    def test_replacement_with_longer_content_is_noticed(self):
        # Not shorter than what was read, so only the changed first line gives it away.
        self.write("old\n")
        reader = TailReader(self.path)
        reader.poll()
        self.write("a different and much longer first line\nand another\n", mode="wb")
        self.assertEqual(self.texts(reader.poll()), ["a different and much longer first line", "and another"])


class OverlongAndResumeTests(TailTestCase):
    def test_overlong_line_is_reported_once_and_later_offsets_stay_right(self):
        self.write("before\n")
        reader = TailReader(self.path)
        reader.poll()
        self.write(b"A" * 150_000)  # no newline yet
        (truncated,) = reader.poll()
        self.assertEqual((truncated[1], len(truncated[2])), (7, MAX_LINE_BYTES))
        self.write(b"A" * 50_000)
        self.assertEqual(reader.poll(), [])  # still the same line: not reported twice
        self.write(b"\nafter\n")
        (after,) = reader.poll()
        self.assertEqual(after[1:], (7 + 200_000 + 1, "after"))
        # ...which is exactly what the batch reader makes of the finished file.
        self.assertEqual([o for o, _ in iter_file_lines(self.path)], [0, 7, after[1]])

    def test_resumes_where_it_is_told_to(self):
        self.write("one\ntwo\nthree\n")
        asked = []

        def resume(source_id):
            asked.append(source_id)
            return 8, False

        reader = TailReader(self.path, resume=resume)
        self.assertEqual([(o, t) for _, o, t in reader.poll()], [(8, "three")])
        self.assertEqual(asked, [file_identity(self.path)])

    def test_resume_is_asked_again_for_a_new_stream(self):
        self.write("one\n")
        asked = []
        reader = TailReader(self.path, resume=lambda sid: asked.append(sid))
        reader.poll()
        self.write("something else\n", mode="wb")
        reader.poll()
        self.assertEqual(len(asked), 2)
        self.assertNotEqual(asked[0], asked[1])


if __name__ == "__main__":
    unittest.main()
